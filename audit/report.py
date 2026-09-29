from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .explain import FIVE_QUESTIONS, evidence_gates, learning_note, path_conclusion_label
from .findings import Finding
from .importers import write_sarif
from .project import ProjectInfo
from .runners.base import RunnerResult


def write_reports(output_dir: Path, project: ProjectInfo, findings: list[Finding], runners: list[RunnerResult], baseline: dict[str, object] | None = None, reviews: dict[str, dict[str, str]] | None = None, surface: dict[str, Any] | None = None, playbook: dict[str, Any] | None = None, authz: dict[str, Any] | None = None, incremental: dict[str, Any] | None = None, engagement: dict[str, Any] | None = None) -> tuple[Path, Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    review_data = reviews or {}
    items = []
    for finding in findings:
        positive, negative = evidence_gates(finding)
        items.append(finding.to_dict() | {
            "learning_note": learning_note(finding),
            "evidence_for": finding.evidence_for or positive,
            "evidence_against": finding.evidence_against or negative,
            "review": review_data.get(finding.fingerprint, {}),
        })
    payload = {
        "schema_version": "1.3", "tool": {"name": "Java Audit Lab", "version": __version__},
        "generated_at": datetime.now(timezone.utc).isoformat(), "project": project.to_dict(),
        "summary": _summary(findings, review_data),
        "surface": surface or {"entries": [], "controls": [], "dynamic_calls": [], "entry_count": 0, "control_count": 0},
        "playbook": playbook or {},
        "authz": authz or {"endpoints": [], "rules": [], "coverage": {}},
        "incremental": incremental or {"enabled": False},
        "engagement": engagement or {
            "report_owner": "未填写", "authorization_ref": "未填写；授权状态由使用者自行确认",
            "scope_note": f"当前项目根目录：{project.root}", "excluded_paths": [],
            "retention_note": "请按授权约定保留或删除源代码、缓存和报告；公开报告前检查敏感信息。",
            "validity_note": "报告仅反映本次扫描时的代码、配置与依赖状态；发生变更后应重新扫描。",
        },
        "baseline": baseline or {"enabled": False, "new": [item.fingerprint for item in findings], "existing": [], "fixed": []},
        "scanners": [result.summary() for result in runners], "findings": items,
        "disclaimer": "扫描结果是待复核线索，不等于已确认漏洞。漏洞是否成立取决于五问证据是否补齐与人工结论。",
    }
    json_path = output_dir / "report.json"
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    write_sarif(output_dir / "report.sarif", findings)
    html_path = output_dir / "report.html"
    html_path.write_text(_render_html(payload), encoding="utf-8")
    md_path = output_dir / "report.md"
    md_path.write_text(_render_markdown(payload), encoding="utf-8")
    return json_path, html_path, md_path


def _summary(findings: list[Finding], reviews: dict[str, dict[str, str]]) -> dict[str, object]:
    counts = {level: 0 for level in ("critical", "high", "medium", "low", "info")}
    scopes: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
        scope = str(finding.metadata.get("scope", "production"))
        scopes[scope] = scopes.get(scope, 0) + 1
    reviewed = sum(1 for finding in findings if reviews.get(finding.fingerprint, {}).get("verdict"))
    return {"total": len(findings), "by_severity": counts, "by_scope": scopes, "reviewed": reviewed}


def _render_html(payload: dict[str, Any]) -> str:
    project, summary, baseline = payload["project"], payload["summary"], payload["baseline"]
    counts = summary["by_severity"]
    risk_score = max((int(item.get("review_priority", 0)) for item in payload["findings"]), default=0)
    new_set = set(baseline.get("new", []))
    cards = "".join(_finding_card(f, f["fingerprint"] in new_set) for f in payload["findings"]) or '<div class="empty-state"><b>没有发现匹配项</b><span>请确认项目包含 Java 文件，并查看扫描器运行状态。</span></div>'
    scanner_cards = "".join(_scanner_card(scanner) for scanner in payload["scanners"])
    engagement_section = _engagement_section(payload)
    authz_section = _authz_section(payload)
    incremental_section = _incremental_section(payload)
    incremental_nav = '<a class="side-link" href="#incremental"><i></i>增量审计</a>' if incremental_section else ""
    spy_ids = "['overview','engagement','scanners','playbook','authz','incremental','findings']" if incremental_section else "['overview','engagement','scanners','playbook','authz','findings']"
    playbook_data = payload.get("playbook") or {}
    playbook_progress = playbook_data.get("progress", {"completed": 0, "partial": 0, "pending": 0, "total": 0})
    playbook_total = int(playbook_progress.get("total", 0)) or 1
    playbook_pct = round(int(playbook_progress.get("completed", 0)) / playbook_total * 100)
    stepper = _stage_stepper(playbook_data.get("stages", []))
    surface_summary = _surface_summary(payload.get("surface") or {})
    initial_reviews = {item["fingerprint"]: item.get("review", {}) for item in payload["findings"] if item.get("review")}
    initial_json = json.dumps(initial_reviews, ensure_ascii=False).replace("</", "<\\/")
    project_json = json.dumps(project["name"], ensure_ascii=False).replace("</", "<\\/")
    report_id = html.escape(f"{project['name']}:{payload['generated_at']}")
    framework_text = " · ".join(project.get("frameworks", [])) or "未识别框架"
    # 数据洞察：三类图表数据
    sev_order = ["critical", "high", "medium", "low", "info"]
    sev_colors = {"critical": "var(--critical)", "high": "var(--high)", "medium": "var(--medium)", "low": "var(--low)", "info": "var(--faint)"}
    sev_labels = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "提示"}
    sev_max = max(counts.values(), default=1) or 1
    sev_bars = "".join(
        f'<div class="bar-row"><span class="bar-label">{sev_labels[s]}</span>'
        f'<div class="bar-track"><i class="bar-fill" style="width:{counts.get(s, 0) / sev_max * 100:.0f}%;background:{sev_colors[s]}"></i></div>'
        f'<span class="bar-value">{counts.get(s, 0)}</span></div>'
        for s in sev_order if counts.get(s, 0) > 0
    ) or '<div class="empty-mini">无严重度数据</div>'
    cwe_counter: dict[str, int] = {}
    for item in payload["findings"]:
        cwe = str(item.get("cwe", "CWE-Unknown"))
        cwe_counter[cwe] = cwe_counter.get(cwe, 0) + 1
    cwe_top = sorted(cwe_counter.items(), key=lambda x: -x[1])[:8]
    cwe_max = max((c for _, c in cwe_top), default=1) or 1
    cwe_bars = "".join(
        f'<div class="bar-row"><span class="bar-label">{html.escape(c)}</span>'
        f'<div class="bar-track"><i class="bar-fill" style="width:{cnt / cwe_max * 100:.0f}%;background:var(--brand)"></i></div>'
        f'<span class="bar-value">{cnt}</span></div>'
        for c, cnt in cwe_top
    ) or '<div class="empty-mini">无 CWE 数据</div>'
    scanner_max = max((int(s.get("finding_count", 0)) for s in payload["scanners"]), default=1) or 1
    scanner_bars = "".join(
        f'<div class="bar-row"><span class="bar-label">{html.escape(s["name"])}</span>'
        f'<div class="bar-track"><i class="bar-fill" style="width:{int(s.get("finding_count", 0)) / scanner_max * 100:.0f}%;background:{"var(--ok)" if s.get("success") else "var(--medium)"}"></i></div>'
        f'<span class="bar-value">{s.get("finding_count", 0)}</span></div>'
        for s in payload["scanners"]
    ) or '<div class="empty-mini">无扫描器数据</div>'
    conclusion_label_map = {"proven": "已证明路径", "inferred": "推测路径", "missing": "路径缺失", "unresolved": "动态未解析"}
    conclusion_colors = {"已证明路径": "var(--critical)", "推测路径": "var(--medium)", "路径缺失": "var(--low)", "动态未解析": "var(--brand)"}
    conclusion_counter: dict[str, int] = {}
    for item in payload["findings"]:
        conclusion = str(((item.get("metadata") or {}).get("path_assessment") or {}).get("conclusion", "missing"))
        label = conclusion_label_map.get(conclusion, "路径缺失")
        conclusion_counter[label] = conclusion_counter.get(label, 0) + 1
    conclusion_order = ["已证明路径", "推测路径", "动态未解析", "路径缺失"]
    conclusion_max = max(conclusion_counter.values(), default=1) or 1
    conclusion_bars = "".join(
        f'<div class="bar-row"><span class="bar-label">{label}</span>'
        f'<div class="bar-track"><i class="bar-fill" style="width:{conclusion_counter.get(label, 0) / conclusion_max * 100:.0f}%;background:{conclusion_colors.get(label, "var(--brand)")}"></i></div>'
        f'<span class="bar-value">{conclusion_counter.get(label, 0)}</span></div>'
        for label in conclusion_order if conclusion_counter.get(label, 0) > 0
    ) or '<div class="empty-mini">无路径结论数据</div>'
    # 规则详情数据（点击规则 ID 时弹窗显示）
    from .runners.builtin import RULES as _ALL_RULES
    rules_json = json.dumps([
        {"id": r.rule_id, "title": r.title, "cwe": r.cwe, "severity": r.severity,
         "confidence": r.confidence, "description": r.description,
         "review_steps": list(r.review_steps), "remediation": r.remediation,
         "pattern": r.pattern.pattern}
        for r in _ALL_RULES
    ], ensure_ascii=False).replace("</", "<" + chr(92) + "/")
    generated = payload["generated_at"].replace("T", " ").replace("+00:00", " UTC")[:20]
    reviewed_start = int(summary.get("reviewed", 0))
    total = int(summary.get("total", 0))
    # JS 块抽到普通字符串变量，避开 f-string 的 {{ }} 转义噩梦
    js_modal_block = r"""// === 规则详情 modal + 键盘快捷键面板 ===
const RULES=%(rules_json)s;
const modal=document.createElement('div');modal.className='modal-overlay';
modal.innerHTML='<div class="modal" role="dialog" aria-modal="true"><div class="modal-head"><div><h3 id="modal-title"></h3><div class="modal-tags" id="modal-tags"></div></div><button class="modal-close" aria-label="关闭">×</button></div><div class="modal-body" id="modal-body"></div></div>';
document.body.appendChild(modal);
modal.addEventListener('click',e=>{if(e.target===modal||e.target.className==='modal-close')modal.classList.remove('open')});
document.addEventListener('keydown',e=>{if(e.key==='Escape')modal.classList.remove('open')});
function openRuleModal(id){const r=RULES.find(x=>x.id===id);if(!r)return;document.getElementById('modal-title').textContent=r.title;
document.getElementById('modal-tags').innerHTML='<span class="tag tag-risk">'+r.severity.toUpperCase()+'</span><span class="tag">'+r.cwe+'</span><span class="tag">置信度 '+r.confidence+'</span><span class="tag">'+r.id+'</span>';
const steps=r.review_steps.map(s=>'<li>'+s+'</li>').join('');
document.getElementById('modal-body').innerHTML='<div class="modal-section"><h4>描述</h4><p>'+r.description+'</p></div><div class="modal-section"><h4>正则模式</h4><code>'+r.pattern.replace(/</g,'&lt;')+'</code></div><div class="modal-section"><h4>复核步骤</h4><ol>'+steps+'</ol></div><div class="modal-section"><h4>修复建议</h4><p>'+r.remediation+'</p></div>';
modal.classList.add('open')}
// 让所有 finding 卡片里的规则 ID tag 可点击
document.querySelectorAll('.finding-kicker .tag').forEach(t=>{const txt=t.textContent.trim();if(/^(JAL-|CWE-)/.test(txt)){t.style.cursor='pointer';t.onclick=()=>{const m=txt.match(/JAL-[A-Z]+-\d+/);if(m)openRuleModal(m[0])}}});
// 键盘快捷键面板：按 ? 弹出
const kbdHelp=document.createElement('button');kbdHelp.className='kbd-help';kbdHelp.textContent='?';kbdHelp.title='键盘快捷键';
document.body.appendChild(kbdHelp);
const kbdList=[['J','下一条发现'],['K','上一条发现'],['?','显示/隐藏此面板'],['Esc','关闭弹窗'],['/','聚焦搜索框']];
kbdHelp.onclick=()=>{modal.querySelector('#modal-title').textContent='键盘快捷键';modal.querySelector('#modal-tags').innerHTML='';modal.querySelector('#modal-body').innerHTML='<div class="modal-section"><div class="kbd-grid">'+kbdList.map(p=>'<kbd>'+p[0]+'</kbd><span>'+p[1]+'</span>').join('')+'</div></div><div class="modal-section"><h4>提示</h4><p>所有复核状态、五问答案、判断信心与备注会自动保存到浏览器 localStorage；下次打开本报告时自动恢复。</p></div>';modal.classList.add('open')};
document.addEventListener('keydown',e=>{if(['INPUT','TEXTAREA','SELECT'].includes(document.activeElement.tagName))return;if(e.key==='?'){e.preventDefault();kbdHelp.click()}if(e.key==='/'){e.preventDefault();document.querySelector('#search').focus()}});""" % {"rules_json": rules_json}

    return f'''<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark"><title>Java Audit Lab · {html.escape(project['name'])}</title>
<style>
:root{{--bg:#f6f7fa;--surface:#fff;--surface-soft:#f8fafc;--ink:#101828;--muted:#667085;--faint:#98a2b3;--line:#e5e8ee;--brand:#4f46e5;--brand-ink:#3730a3;--brand-soft:#eef0ff;--cyan:#0891b2;--critical:#d92d20;--critical-soft:#fee4e2;--high:#e5484d;--high-soft:#fff1f0;--medium:#d97706;--medium-soft:#fff7e8;--low:#2e90fa;--low-soft:#eff6ff;--ok:#12b76a;--ok-soft:#ecfdf3;--shadow:0 1px 2px rgba(16,24,40,.05),0 10px 28px rgba(16,24,40,.07);--shadow-lg:0 2px 4px rgba(16,24,40,.05),0 18px 44px rgba(16,24,40,.1);--code:#111827;--code-ink:#d1fae5;--radius:14px}}
html[data-theme="dark"]{{--bg:#0b101d;--surface:#141b2c;--surface-soft:#101728;--ink:#e9eef8;--muted:#9aa5bd;--faint:#6f7b94;--line:#232c45;--brand:#818cf8;--brand-ink:#a5b4fc;--brand-soft:#20265a;--critical:#f04438;--critical-soft:#3b1c1a;--high:#f87171;--high-soft:#3b1d1d;--medium:#fbbf24;--medium-soft:#3a2d10;--low:#60a5fa;--low-soft:#16233f;--ok:#34d399;--ok-soft:#123527;--shadow:0 1px 2px rgba(0,0,0,.2),0 14px 34px rgba(0,0,0,.32);--shadow-lg:0 2px 4px rgba(0,0,0,.2),0 20px 50px rgba(0,0,0,.4);--code:#080d19;--code-ink:#bbf7d0}}
*{{box-sizing:border-box}}html{{scroll-behavior:smooth;max-width:100%;overflow-x:clip}}body{{margin:0;max-width:100%;overflow-x:clip;background:var(--bg);color:var(--ink);font:14px/1.6 Inter,"Segoe UI","Microsoft YaHei",system-ui,sans-serif;transition:background .2s,color .2s}}button,input,select,textarea{{font:inherit}}button,a{{-webkit-tap-highlight-color:transparent}}a{{color:var(--brand);text-decoration:none}}.app{{display:grid;grid-template-columns:270px minmax(0,1fr);width:100%;min-width:0;min-height:100vh}}
.sidebar{{position:sticky;top:0;height:100vh;display:flex;flex-direction:column;gap:16px;padding:22px 20px;background:var(--surface);border-right:1px solid var(--line);overflow-y:auto}}
.brand{{display:flex;align-items:center;gap:11px;font-weight:800;letter-spacing:-.3px;font-size:15px}}.logo{{display:grid;place-items:center;width:36px;height:36px;border-radius:11px;background:linear-gradient(135deg,var(--brand),var(--brand-ink));color:#fff;font-weight:800;box-shadow:0 4px 12px color-mix(in srgb,var(--brand) 40%,transparent)}}.version{{font-size:10px;font-weight:600;color:var(--brand-ink);background:var(--brand-soft);border-radius:20px;padding:2px 8px;margin-left:2px}}
.project-brief{{padding:12px 13px;background:var(--surface-soft);border:1px solid var(--line);border-radius:12px;font-size:12px;color:var(--muted);display:grid;gap:5px}}.project-brief b{{color:var(--ink);font-size:13px}}.project-brief span{{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.side-nav{{display:grid;gap:3px}}.side-link{{display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:10px;color:var(--muted);font-weight:600;font-size:13px;transition:.15s}}.side-link i{{width:7px;height:7px;border-radius:50%;background:var(--line);transition:.15s}}.side-link:hover{{color:var(--ink);background:var(--surface-soft)}}.side-link.active{{color:var(--brand-ink);background:var(--brand-soft)}}.side-link.active i{{background:var(--brand)}}
.side-ring{{display:flex;align-items:center;gap:12px;padding:12px;border:1px solid var(--line);border-radius:12px;background:var(--surface-soft)}}.side-ring svg{{flex:none}}.ring-bg{{fill:none;stroke:var(--line);stroke-width:6.5}}.ring-fg{{fill:none;stroke:var(--brand);stroke-width:6.5;stroke-linecap:round;stroke-dasharray:188.5;stroke-dashoffset:188.5;transform:rotate(-90deg);transform-origin:center;transition:stroke-dashoffset .45s ease}}.ring-text{{fill:var(--ink);font-size:12.5px;font-weight:800;text-anchor:middle}}.side-ring-meta b{{display:block;font-size:15px}}.side-ring-meta span{{font-size:11px;color:var(--muted)}}
.side-stage{{font-size:11px;color:var(--muted);display:grid;gap:6px}}.side-stage .progress-track{{height:6px}}
.icon-btn{{width:36px;height:36px;border:1px solid var(--line);border-radius:10px;background:var(--surface);color:var(--muted);cursor:pointer;font-size:14px}}.icon-btn:hover{{color:var(--brand);border-color:var(--brand)}}
.main{{width:100%;max-width:100%;min-width:0;overflow-x:clip}}.topbar{{position:sticky;top:0;z-index:30;display:flex;align-items:center;justify-content:space-between;gap:16px;min-width:0;padding:14px clamp(18px,2vw,36px);background:color-mix(in srgb,var(--bg) 82%,transparent);backdrop-filter:blur(12px);border-bottom:1px solid var(--line)}}.topbar>div:first-child{{min-width:0}}.topbar h1{{margin:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:17px;letter-spacing:-.3px}}.topbar .meta-chips{{display:flex;flex-wrap:wrap;gap:6px;margin-top:4px}}.meta-chips span{{font-size:11px;color:var(--muted);background:var(--surface);border:1px solid var(--line);border-radius:20px;padding:2px 9px}}.top-actions{{display:flex;flex-wrap:wrap;justify-content:flex-end;gap:8px;flex:none}}
.btn{{display:inline-flex;align-items:center;gap:6px;height:34px;padding:0 13px;border:1px solid var(--line);border-radius:9px;background:var(--surface);color:var(--ink);font-size:12.5px;font-weight:600;cursor:pointer;transition:.15s}}.btn:hover{{border-color:var(--brand);color:var(--brand-ink);box-shadow:var(--shadow)}}.btn-primary{{background:var(--brand);border-color:var(--brand);color:#fff}}.btn-primary:hover{{background:var(--brand-ink);color:#fff}}.theme-toggle{{min-width:96px;justify-content:center}}.theme-icon{{font-size:15px}}
.page{{width:100%;max-width:none;min-width:0;margin:0;padding:24px clamp(18px,2vw,36px) 52px;display:grid;gap:27px}}.page>*,.section,.overview>*,.dashboard-grid>*,.scanner-grid>*,.stepper>*,.finding,.finding-main,.finding-head>*{{min-width:0}}
.overview{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}}.metric{{position:relative;overflow:hidden;padding:15px 16px 13px;background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow)}}.metric:before{{content:"";position:absolute;inset:0 auto auto 0;width:100%;height:3px;background:var(--dot)}}.metric-label{{display:flex;align-items:center;gap:7px;font-size:11.5px;font-weight:700;color:var(--muted)}}.dot{{width:7px;height:7px;border-radius:50%;background:var(--dot)}}.metric strong{{display:block;font-size:27px;font-weight:800;letter-spacing:-.8px;font-variant-numeric:tabular-nums;margin-top:5px}}.metric small{{color:var(--faint);font-size:11px}}
.section{{display:grid;gap:14px;scroll-margin-top:78px}}.section-head{{display:flex;justify-content:space-between;align-items:end;gap:18px}}.section-head h2{{margin:0;font-size:17px;letter-spacing:-.3px}}.section-head p{{margin:3px 0 0;color:var(--muted);font-size:12.5px}}
.card{{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow)}}
.scanner-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px}}.scanner{{padding:14px 15px;background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);transition:.15s}}.scanner:hover{{box-shadow:var(--shadow);transform:translateY(-1px)}}.scanner-top{{display:flex;justify-content:space-between;align-items:start;gap:10px}}.scanner-name{{font-weight:700;font-size:13.5px}}.scanner-status{{display:inline-flex;align-items:center;gap:6px;font-size:11px;color:var(--status,var(--faint));font-weight:700;margin-top:2px}}.scanner-status i{{width:7px;height:7px;border-radius:50%;background:var(--status,var(--faint))}}.scanner-count{{font-size:22px;font-weight:800;color:var(--ink);font-variant-numeric:tabular-nums}}.scanner p{{margin:8px 0 0;font-size:11.5px;color:var(--muted)}}
.method-card{{display:flex;gap:13px;padding:15px 17px;background:linear-gradient(120deg,var(--brand-soft),var(--surface));border:1px solid color-mix(in srgb,var(--brand) 22%,var(--line));border-radius:var(--radius)}}.method-card>div{{min-width:0}}.method-icon{{flex:none;display:grid;place-items:center;width:32px;height:32px;border-radius:9px;background:var(--brand);color:#fff;font-weight:800}}.method-card b{{font-size:13px}}.method-card p{{margin:3px 0 0;overflow-wrap:anywhere;font-size:12px;color:var(--muted)}}
.stepper{{display:grid;grid-template-columns:repeat(auto-fill,minmax(215px,1fr));gap:12px}}.step{{position:relative;padding:14px 15px;background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);overflow:hidden;transition:.15s}}.step:hover{{box-shadow:var(--shadow)}}.step:before{{content:"";position:absolute;inset:0 auto auto 0;height:3px;width:100%;background:var(--step-color,var(--faint))}}.step-top{{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}}.step-num{{display:grid;place-items:center;width:26px;height:26px;border-radius:8px;background:color-mix(in srgb,var(--step-color,var(--faint)) 16%,transparent);color:var(--step-color,var(--faint));font-size:12px;font-weight:800}}.step-badge{{font-size:10.5px;font-weight:700;color:var(--step-color,var(--faint));background:color-mix(in srgb,var(--step-color,var(--faint)) 13%,transparent);border-radius:20px;padding:2px 9px}}.step b{{display:block;font-size:13.5px;letter-spacing:-.2px}}.step>p{{margin:5px 0 0;font-size:11.5px;color:var(--muted);line-height:1.5}}.step details{{margin-top:9px}}.step summary{{cursor:pointer;font-size:11px;color:var(--brand-ink);font-weight:600}}.step ul{{margin:6px 0 0;padding-left:16px;font-size:11px;color:var(--muted);display:grid;gap:3px}}.step li.gap-item{{color:var(--medium)}}
.progress{{display:flex;align-items:center;gap:9px;font-size:12px;color:var(--muted);white-space:nowrap}}.progress-track{{display:block;width:150px;height:6px;border-radius:6px;background:var(--line);overflow:hidden}}.progress-bar{{display:block;height:100%;border-radius:6px;background:linear-gradient(90deg,var(--brand),var(--cyan));transition:width .35s ease}}
.kbd-help{{position:fixed;bottom:24px;right:24px;z-index:50;width:42px;height:42px;border-radius:50%;border:1px solid var(--line);background:var(--surface);color:var(--muted);cursor:pointer;font-size:15px;font-weight:700;box-shadow:var(--shadow-lg);transition:.15s}}.kbd-help:hover{{color:var(--brand);border-color:var(--brand);transform:scale(1.05)}}.kbd-grid{{display:grid;grid-template-columns:auto 1fr;gap:10px 18px;font-size:13px}}.kbd-grid kbd{{display:inline-block;padding:2px 9px;background:var(--surface-soft);border:1px solid var(--line);border-bottom-width:2px;border-radius:6px;font:12px ui-monospace,Consolas,monospace;color:var(--ink);min-width:24px;text-align:center}}.kbd-grid span{{color:var(--muted);align-self:center}}
@keyframes fade{{from{{opacity:0}}to{{opacity:1}}}}@keyframes pop{{from{{opacity:0;transform:scale(.92) translateY(8px)}}to{{opacity:1;transform:scale(1) translateY(0)}}}}@keyframes slideUp{{from{{opacity:0;transform:translateY(10px)}}to{{opacity:1;transform:translateY(0)}}}}.finding{{animation:slideUp .25s ease both}}
.dashboard-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px}}.chart-card{{padding:16px 18px;background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow);transition:.18s}}.chart-card:hover{{box-shadow:var(--shadow-lg);transform:translateY(-1px)}}.chart-head{{display:flex;justify-content:space-between;align-items:baseline;gap:10px;margin-bottom:14px}}.chart-head b{{font-size:13.5px;letter-spacing:-.2px}}.chart-head small{{font-size:11px;color:var(--faint)}}.chart-body{{display:grid;gap:9px}}.bar-row{{display:grid;grid-template-columns:90px 1fr 32px;align-items:center;gap:10px;font-size:12px}}.bar-label{{color:var(--muted);font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}.bar-track{{height:9px;border-radius:6px;background:var(--surface-soft);overflow:hidden;position:relative}}.bar-fill{{display:block;height:100%;border-radius:6px;transition:width .6s cubic-bezier(.4,0,.2,1);box-shadow:0 0 0 1px color-mix(in srgb,#000 5%,transparent)}}.bar-value{{text-align:right;font-weight:700;font-variant-numeric:tabular-nums;color:var(--ink)}}.empty-mini{{color:var(--faint);font-size:12px;text-align:center;padding:18px 0}}
.modal-overlay{{position:fixed;inset:0;background:rgba(16,24,40,.55);backdrop-filter:blur(4px);z-index:200;display:none;align-items:center;justify-content:center;padding:24px;animation:fade .18s ease}}.modal-overlay.open{{display:flex}}.modal{{max-width:620px;width:100%;max-height:80vh;overflow-y:auto;background:var(--surface);border:1px solid var(--line);border-radius:18px;box-shadow:var(--shadow-lg);padding:24px 26px;animation:pop .22s cubic-bezier(.34,1.56,.64,1)}}.modal-head{{display:flex;justify-content:space-between;align-items:start;gap:14px;margin-bottom:14px;padding-bottom:14px;border-bottom:1px solid var(--line)}}.modal-head h3{{margin:0;font-size:17px;letter-spacing:-.3px}}.modal-head .modal-tags{{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}}.modal-close{{flex:none;width:30px;height:30px;border:1px solid var(--line);border-radius:9px;background:var(--surface);color:var(--muted);cursor:pointer;font-size:16px;line-height:1}}.modal-close:hover{{color:var(--critical);border-color:var(--critical)}}.modal-section{{margin:14px 0}}.modal-section h4{{margin:0 0 6px;font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;font-weight:700}}.modal-section p{{margin:0;font-size:13px;line-height:1.65}}.modal-section code{{display:block;padding:12px 14px;margin:6px 0;background:var(--code);color:var(--code-ink);border-radius:9px;font:12.5px/1.6 ui-monospace,Consolas,monospace;overflow-x:auto;white-space:pre-wrap;word-break:break-all}}.modal-section ol{{margin:6px 0 0;padding-left:20px;font-size:13px;line-height:1.7}}
.kbd-help{{position:fixed;bottom:24px;right:24px;z-index:50;width:42px;height:42px;border-radius:50%;border:1px solid var(--line);background:var(--surface);color:var(--muted);cursor:pointer;font-size:15px;font-weight:700;box-shadow:var(--shadow-lg);transition:.15s}}.kbd-help:hover{{color:var(--brand);border-color:var(--brand);transform:scale(1.05)}}.kbd-grid{{display:grid;grid-template-columns:auto 1fr;gap:10px 18px;font-size:13px}}.kbd-grid kbd{{display:inline-block;padding:2px 9px;background:var(--surface-soft);border:1px solid var(--line);border-bottom-width:2px;border-radius:6px;font:12px ui-monospace,Consolas,monospace;color:var(--ink);min-width:24px;text-align:center}}.kbd-grid span{{color:var(--muted);align-self:center}}
@keyframes fade{{from{{opacity:0}}to{{opacity:1}}}}@keyframes pop{{from{{opacity:0;transform:scale(.92) translateY(8px)}}to{{opacity:1;transform:scale(1) translateY(0)}}}}@keyframes slideUp{{from{{opacity:0;transform:translateY(10px)}}to{{opacity:1;transform:translateY(0)}}}}.finding{{animation:slideUp .25s ease both}}
.group-header{{display:flex;align-items:center;gap:10px;padding:10px 14px;margin:14px 0 4px;background:color-mix(in srgb,var(--brand) 8%,var(--surface));border:1px solid color-mix(in srgb,var(--brand) 25%,var(--line));border-radius:var(--radius);font-size:12.5px;font-weight:600;color:var(--ink);position:sticky;top:108px;z-index:15;backdrop-filter:blur(8px)}}.group-header .group-meta{{font-weight:400;color:var(--muted);font-size:11px}}.group-header .group-btn{{margin-left:auto;border:none;background:transparent;color:var(--muted);cursor:pointer;font-size:11px;padding:2px 6px}}
.toolbar{{position:sticky;top:64px;z-index:20;display:flex;flex-wrap:wrap;gap:9px;align-items:center;padding:12px;background:color-mix(in srgb,var(--bg) 88%,transparent);backdrop-filter:blur(12px);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow)}}.field{{height:36px;padding:0 12px;border:1px solid var(--line);border-radius:9px;background:var(--surface);color:var(--ink);font-size:12.5px}}.field:focus{{outline:2px solid color-mix(in srgb,var(--brand) 35%,transparent);border-color:var(--brand)}}input.field{{flex:1;min-width:200px}}.actions{{display:flex;gap:7px;margin-left:auto}}
.list-meta{{display:flex;justify-content:space-between;align-items:center;gap:14px;font-size:12px;color:var(--muted);flex-wrap:wrap}}
.finding{{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow);overflow:hidden;margin-bottom:14px;transition:.15s;position:relative}}.finding:hover{{box-shadow:var(--shadow-lg)}}.finding:before{{content:"";position:absolute;inset:0 auto 0 0;width:4px;background:var(--sev,var(--faint))}}.finding[data-severity="critical"]{{--sev:var(--critical)}}.finding[data-severity="high"]{{--sev:var(--high)}}.finding[data-severity="medium"]{{--sev:var(--medium)}}.finding[data-severity="low"]{{--sev:var(--low)}}.finding[data-status="confirmed"]{{border-color:color-mix(in srgb,var(--critical) 45%,var(--line))}}.finding[data-status="false-positive"]{{opacity:.72}}.finding.hidden{{display:none}}
.finding-main{{padding:18px 20px 14px 24px}}.finding-head{{display:flex;flex-wrap:wrap;justify-content:space-between;gap:14px;align-items:start}}.finding-kicker{{display:flex;flex-wrap:wrap;gap:5px;margin-bottom:8px}}.tag{{font-size:10.5px;font-weight:700;color:var(--muted);background:var(--surface-soft);border:1px solid var(--line);border-radius:20px;padding:2px 9px}}.tag-risk{{color:#fff;border:0;background:var(--sev,var(--brand))}}.tag-new{{color:var(--cyan);border-color:var(--cyan);background:color-mix(in srgb,var(--cyan) 10%,transparent)}}h3{{margin:0;font-size:15.5px;letter-spacing:-.2px}}.description{{margin:8px 0 10px;overflow-wrap:anywhere;color:var(--muted);font-size:12.5px}}.finding pre{{margin:0;padding:12px 14px;background:var(--code);color:var(--code-ink);border-radius:10px;font:12px/1.6 ui-monospace,"Cascadia Code",Consolas,monospace;overflow-x:auto;white-space:pre-wrap;word-break:break-all}}
.finding details{{margin:0;border-top:1px solid var(--line);padding:0 20px 0 24px}}.finding details>summary{{cursor:pointer;padding:11px 0;font-size:12.5px;font-weight:700;color:var(--muted);list-style:none}}.finding details>summary::-webkit-details-marker{{display:none}}.finding details>summary:before{{content:"▸";display:inline-block;margin-right:7px;color:var(--brand);transition:transform .15s}}.finding details[open]>summary:before{{transform:rotate(90deg)}}.finding details>summary:hover{{color:var(--brand-ink)}}.detail-body{{padding:0 0 14px}}
.trace{{margin:0;padding-left:18px;font-size:12px;color:var(--muted);display:grid;gap:6px}}.trace code{{color:var(--brand-ink);background:var(--brand-soft);border-radius:5px;padding:1px 6px;font-size:11px}}
.priority-explain{{display:grid;gap:7px}}.factor{{display:grid;grid-template-columns:110px 1fr 42px;gap:10px;align-items:center;padding:8px 10px;background:var(--surface-soft);border-radius:8px}}.factor span{{font-size:12px;color:var(--muted)}}.factor b{{text-align:right;color:var(--brand);font-variant-numeric:tabular-nums}}
.flow-graph{{display:flex;align-items:stretch;overflow-x:auto;padding:7px 2px 12px}}.flow-node{{flex:0 0 185px;padding:11px;border:1px solid var(--line);border-radius:10px;background:var(--surface-soft)}}.flow-node b{{display:block;color:var(--ink);font-size:11px;margin-bottom:5px}}.flow-node span{{display:block;color:var(--muted);font-size:11px}}.flow-arrow{{flex:0 0 34px;display:grid;place-items:center;color:var(--brand);font-size:18px}}
.gate{{display:grid;grid-template-columns:1fr 1fr;gap:12px}}.gate-panel{{padding:13px 14px;border-radius:11px;border:1px solid var(--line)}}.gate-panel b{{display:block;font-size:12px;margin-bottom:7px}}.gate-panel ul{{margin:0;padding-left:16px;font-size:12px;color:var(--muted);display:grid;gap:4px}}.gate-panel.positive{{background:var(--critical-soft);border-color:color-mix(in srgb,var(--critical) 30%,var(--line))}}.gate-panel.positive b{{color:var(--critical)}}.gate-panel.negative{{background:var(--ok-soft);border-color:color-mix(in srgb,var(--ok) 30%,var(--line))}}.gate-panel.negative b{{color:var(--ok)}}
.guide{{margin:0 20px 16px 24px;padding:15px 16px;border:1px solid color-mix(in srgb,var(--brand) 24%,var(--line));border-radius:11px;background:linear-gradient(120deg,var(--brand-soft),var(--surface))}}.guide-head{{display:flex;justify-content:space-between;align-items:center;margin-bottom:6px}}.guide-head b{{font-size:13px}}.guide-head span{{font-size:10.5px;color:var(--muted)}}.guide-row{{display:grid;grid-template-columns:1fr auto;gap:12px;align-items:center;padding:9px 0;border-top:1px solid var(--line)}}.guide-row p{{margin:0;font-size:12px}}.answers{{display:flex;gap:4px}}.answer{{height:29px;padding:0 10px;border:1px solid var(--line);border-radius:7px;background:var(--surface);color:var(--muted);cursor:pointer;font-size:11px;font-weight:600;transition:.12s}}.answer:hover{{border-color:var(--brand);color:var(--brand-ink)}}.answer.active{{background:var(--brand);border-color:var(--brand);color:#fff}}
.review{{margin:0 20px 18px 24px;padding:15px 16px;border:1px solid var(--line);border-radius:11px;background:var(--surface-soft);display:grid;gap:13px}}.review-head{{display:flex;align-items:start;justify-content:space-between;gap:16px}}.review-head b{{display:block;font-size:13px}}.review-head small{{display:block;margin-top:2px;color:var(--muted);font-size:11px}}.review-state{{flex:none;padding:3px 9px;border:1px solid var(--line);border-radius:20px;background:var(--surface);color:var(--muted);font-size:10.5px;font-weight:700}}.review-grid{{display:grid;grid-template-columns:minmax(280px,360px) minmax(320px,1fr);gap:16px;align-items:stretch}}.review-decision{{display:grid;align-content:start;gap:11px;padding-right:16px;border-right:1px solid var(--line)}}.review-label,.review-notes>span{{display:block;margin-bottom:6px;color:var(--muted);font-size:11px;font-weight:700}}.verdicts{{display:flex;gap:7px;flex-wrap:wrap}}[data-verdict]{{height:31px;padding:0 13px;border:1px solid var(--line);border-radius:8px;background:var(--surface);color:var(--muted);cursor:pointer;font-size:12px;font-weight:700;transition:.12s}}[data-verdict].active[data-verdict="confirmed"]{{background:var(--critical);border-color:var(--critical);color:#fff}}[data-verdict].active[data-verdict="false-positive"]{{background:var(--ok);border-color:var(--ok);color:#fff}}[data-verdict].active[data-verdict="uncertain"]{{background:var(--medium);border-color:var(--medium);color:#fff}}.review-notes{{display:block}}.review textarea{{width:100%;min-height:88px;padding:10px 11px;border:1px solid var(--line);border-radius:9px;background:var(--surface);color:var(--ink);font-size:12px;resize:vertical}}.confidence{{display:grid;grid-template-columns:auto auto minmax(120px,1fr);align-items:center;gap:10px;font-size:11.5px;color:var(--muted)}}.confidence input{{width:100%;accent-color:var(--brand)}}[data-confidence-value]{{font-weight:800;color:var(--brand-ink);font-variant-numeric:tabular-nums}}
.dossier-grid{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}}.dossier-card{{padding:14px 15px;background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow)}}.dossier-card>span{{display:block;color:var(--muted);font-size:10.5px;font-weight:700;text-transform:uppercase;letter-spacing:.35px}}.dossier-card>b{{display:block;margin-top:5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:13px}}.dossier-card>small{{display:block;margin-top:4px;color:var(--faint);font-size:10.5px;line-height:1.5}}.scope-sheet{{display:grid;grid-template-columns:minmax(0,1.3fr) minmax(0,1fr);overflow:hidden;background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow)}}.scope-block{{padding:16px 18px;min-width:0}}.scope-block+ .scope-block{{border-left:1px solid var(--line)}}.scope-block h3{{margin:0 0 9px;font-size:13px}}.scope-list{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px 16px}}.scope-item{{display:flex;align-items:center;justify-content:space-between;gap:12px;padding-bottom:7px;border-bottom:1px solid var(--line);color:var(--muted);font-size:11.5px}}.scope-item b{{color:var(--ink);font-variant-numeric:tabular-nums}}.scope-copy{{display:grid;gap:9px}}.scope-copy div{{min-width:0}}.scope-copy b{{display:block;color:var(--muted);font-size:10.5px}}.scope-copy span{{display:block;margin-top:2px;overflow-wrap:anywhere;color:var(--ink);font-size:11.5px}}.extension-list{{display:flex;flex-wrap:wrap;gap:6px;margin-top:11px}}.extension-list span{{padding:2px 8px;border:1px solid var(--line);border-radius:20px;background:var(--surface-soft);color:var(--muted);font-size:10.5px}}
.authz-tools{{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}}.authz-summary{{display:flex;flex-wrap:wrap;gap:6px}}.authz-chip{{font-size:11px;color:var(--muted);background:var(--surface);border:1px solid var(--line);border-radius:20px;padding:3px 10px}}.authz-chip b{{color:var(--ink)}}.authz-filters{{display:flex;gap:8px;align-items:center}}.authz-filters input{{width:min(260px,28vw)}}.authz-count{{color:var(--muted);font-size:11px;white-space:nowrap}}.authz-shell{{overflow:hidden}}.authz-scroll{{max-height:min(68vh,760px);overflow:auto}}.authz-table{{width:100%;min-width:980px;border-collapse:separate;border-spacing:0;table-layout:fixed;font-size:12px}}.authz-table th{{position:sticky;top:0;z-index:2;padding:10px 12px;border-bottom:1px solid var(--line);background:var(--surface-soft);color:var(--muted);font-size:10.5px;letter-spacing:.25px;text-align:left;text-transform:uppercase}}.authz-table td{{padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top;overflow:hidden}}.authz-table tbody tr:nth-child(even){{background:color-mix(in srgb,var(--surface-soft) 62%,transparent)}}.authz-table tbody tr:hover{{background:var(--brand-soft)}}.authz-route{{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--brand-ink);font:600 11.5px/1.5 ui-monospace,Consolas,monospace}}.authz-meta{{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin-top:2px;color:var(--faint);font-size:10.5px}}.method-badge,.status-badge{{display:inline-flex;align-items:center;min-height:24px;padding:2px 8px;border-radius:7px;background:var(--surface-soft);border:1px solid var(--line);font-size:10.5px;font-weight:800;white-space:nowrap}}.status-badge{{color:var(--badge-color,var(--muted));border-color:color-mix(in srgb,var(--badge-color,var(--line)) 32%,var(--line));background:color-mix(in srgb,var(--badge-color,var(--surface)) 8%,var(--surface))}}.authz-cell-main{{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}.authz-cell-sub{{display:block;margin-top:3px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--faint);font-size:10.5px}}
.empty-state{{padding:60px 20px;text-align:center;color:var(--muted);display:grid;gap:6px}}footer{{text-align:center;color:var(--faint);font-size:11.5px;padding:26px 0 10px;border-top:1px solid var(--line)}}
button.location{{display:block;max-width:min(54vw,840px);overflow:hidden;text-overflow:ellipsis;border:0;background:transparent;cursor:pointer;font-size:11.5px;color:var(--muted);font-family:ui-monospace,Consolas,monospace;white-space:nowrap;text-align:right}}button.location:hover{{color:var(--brand)}}
.mobile-top{{display:none}}
@media(max-width:1080px){{.app{{grid-template-columns:minmax(0,1fr)}}.sidebar{{display:none}}.mobile-top{{display:flex;position:sticky;top:0;z-index:40;align-items:center;justify-content:space-between;padding:12px 20px;background:var(--surface);border-bottom:1px solid var(--line)}}}}
@media(max-width:1100px){{.dossier-grid{{grid-template-columns:repeat(2,minmax(0,1fr))}}.scope-sheet{{grid-template-columns:1fr}}.scope-block+ .scope-block{{border-left:0;border-top:1px solid var(--line)}}}}
@media(max-width:900px){{.review-grid{{grid-template-columns:1fr}}.review-decision{{padding-right:0;padding-bottom:13px;border-right:0;border-bottom:1px solid var(--line)}}}}
@media(max-width:760px){{.mobile-top{{padding:10px 14px}}.topbar{{position:static;flex-direction:column;align-items:stretch;padding:12px 14px}}.top-actions{{justify-content:flex-start;width:100%;overflow-x:auto;padding-bottom:2px}}.top-actions .btn{{flex:none}}.theme-toggle{{display:none}}.page{{padding:18px 14px 44px;gap:24px}}.overview{{grid-template-columns:repeat(2,minmax(0,1fr))}}.dashboard-grid,.scanner-grid,.stepper{{grid-template-columns:minmax(0,1fr)}}.section-head{{flex-direction:column;align-items:start}}.toolbar{{position:static;align-items:stretch}}.toolbar .field,input.field{{width:100%;min-width:0}}.actions{{width:100%;margin-left:0}}.actions .btn{{width:100%;justify-content:center}}.group-header{{top:0}}.finding-head{{flex-direction:column}}button.location{{width:100%;max-width:100%;text-align:left}}.guide-row{{grid-template-columns:1fr}}.answers{{flex-wrap:wrap}}.factor{{grid-template-columns:90px minmax(0,1fr) 36px}}.gate{{grid-template-columns:1fr}}.guide{{margin:0 12px 16px 16px}}.review{{margin:0 12px 16px 16px}}.review-head{{flex-direction:column;gap:7px}}.confidence{{grid-template-columns:auto auto minmax(80px,1fr)}}.authz-tools,.authz-filters{{align-items:stretch;flex-direction:column}}.authz-filters{{width:100%}}.authz-filters input,.authz-filters select{{width:100%}}}}
@media(max-width:520px){{.dossier-grid,.scope-list{{grid-template-columns:1fr}}}}
@media(max-width:420px){{.overview{{grid-template-columns:1fr}}.finding-main{{padding:16px 14px 12px 18px}}.finding details{{padding:0 14px 0 18px}}.progress-track{{width:100px}}}}
@media print{{.sidebar,.mobile-top,.toolbar,.actions,.review,.guide,.icon-btn{{display:none!important}}.app{{grid-template-columns:1fr}}.page{{padding:0}}.finding{{break-inside:avoid;box-shadow:none}}details{{display:block}}details>.detail-body{{display:block}}body{{background:#fff}}}}
</style></head><body>
<div class="mobile-top"><div class="brand"><span class="logo">JA</span><span>Java Audit Lab <span class="version">{__version__}</span></span></div><button class="icon-btn" id="theme-m" title="切换主题">◐</button></div>
<div class="app"><aside class="sidebar"><div class="brand"><span class="logo">JA</span><span>Java Audit Lab <span class="version">{__version__}</span></span></div>
<div class="project-brief"><b>{html.escape(project['name'])}</b><span>{html.escape(project['build_system'])} · {project['java_files']} 个 Java 文件</span><span>{html.escape(framework_text)}</span><span>{html.escape(generated)}</span></div>
<nav class="side-nav"><a class="side-link" href="#overview"><i></i>概览</a><a class="side-link" href="#engagement"><i></i>审计档案</a><a class="side-link" href="#scanners"><i></i>扫描器状态</a><a class="side-link" href="#playbook"><i></i>审计阶段</a><a class="side-link" href="#authz"><i></i>权限矩阵</a>{incremental_nav}<a class="side-link" href="#findings"><i></i>复核工作区</a></nav>
<div class="side-stage"><span>审计阶段 <b>{playbook_progress.get('completed', 0)}</b> / {playbook_total}</span><i class="progress-track"><i class="progress-bar" style="width:{playbook_pct}%"></i></i></div>
<div class="side-ring"><svg viewBox="0 0 72 72" width="64" height="64"><circle class="ring-bg" cx="36" cy="36" r="30"/><circle class="ring-fg" id="ring-fg" cx="36" cy="36" r="30"/><text class="ring-text" id="ring-text" x="36" y="41">0%</text></svg><div class="side-ring-meta"><b id="ring-count">{reviewed_start} / {total}</b><span>人工复核进度</span></div></div>
</aside>
<main class="main" data-report="{report_id}"><div class="topbar"><div><h1>{html.escape(project['name'])}</h1><div class="meta-chips"><span>{html.escape(project['build_system'])}</span><span>{project['java_files']} 文件</span><span>{html.escape(framework_text)}</span><span>最高关注指数 {risk_score}</span></div></div><div class="top-actions"><button class="btn theme-toggle" id="theme" title="切换明暗主题"><span class="theme-icon">☾</span><span data-theme-label>深色模式</span></button><button class="btn btn-primary" id="export">↓ 导出复核</button><a class="btn" href="report.json" download>JSON</a><a class="btn" href="report.sarif" download>SARIF</a><a class="btn" href="report.md" download>MD</a></div></div>
<div class="page">
<section class="overview" id="overview"><div class="metric" style="--dot:var(--brand)"><span class="metric-label"><i class="dot"></i>全部线索</span><strong>{total}</strong><small>等待人工判断</small></div><div class="metric" style="--dot:var(--critical)"><span class="metric-label"><i class="dot"></i>严重</span><strong>{counts['critical']}</strong><small>优先复核</small></div><div class="metric" style="--dot:var(--high)"><span class="metric-label"><i class="dot"></i>高危</span><strong>{counts['high']}</strong><small>需要关注</small></div><div class="metric" style="--dot:var(--medium)"><span class="metric-label"><i class="dot"></i>中危</span><strong>{counts['medium']}</strong><small>结合上下文</small></div><div class="metric" style="--dot:var(--cyan)"><span class="metric-label"><i class="dot"></i>基线新增</span><strong>{len(baseline.get('new', []))}</strong><small>本轮变化</small></div><div class="metric" style="--dot:var(--ok)"><span class="metric-label"><i class="dot"></i>已修复</span><strong>{len(baseline.get('fixed', []))}</strong><small>相对基线</small></div></section>{engagement_section}


<section class="section" id="dashboard"><div class="section-head"><div><h2>数据洞察</h2><p>四类视图协同：严重度分布、CWE 类型聚集、扫描器贡献、证据结论等级</p></div></div><div class="dashboard-grid"><div class="chart-card"><div class="chart-head"><b>严重度分布</b><small>按数量归一</small></div><div class="chart-body">{sev_bars}</div></div><div class="chart-card"><div class="chart-head"><b>CWE 类型聚集</b><small>前 8 类</small></div><div class="chart-body">{cwe_bars}</div></div><div class="chart-card"><div class="chart-head"><b>扫描器贡献</b><small>各扫描器命中数</small></div><div class="chart-body">{scanner_bars}</div></div><div class="chart-card"><div class="chart-head"><b>证据结论分布</b><small>路径证据等级</small></div><div class="chart-body">{conclusion_bars}</div></div></div></section>
<section class="section" id="scanners"><div class="section-head"><div><h2>扫描器运行状态</h2><p>任一扫描器失败都不会丢失其他扫描证据</p></div></div><div class="scanner-grid">{scanner_cards}</div><div class="method-card"><span class="method-icon">?</span><div><b>可证伪复核</b><p>{html.escape(payload['disclaimer'])} 请同时寻找支持风险的证据与能够推翻风险假设的安全控制。</p></div></div></section>
<section class="section" id="playbook"><div class="section-head"><div><h2>审计阶段 · Evidence Driven Playbook</h2><p>每个阶段只由可核验证据或人工回答驱动；『部分完成』表示仍有证据缺口</p></div><div class="progress"><span>已完成 <b>{playbook_progress.get('completed', 0)}</b> / {playbook_total}</span><i class="progress-track"><i class="progress-bar" style="width:{playbook_pct}%"></i></i></div></div><div class="stepper">{stepper}</div><div class="method-card"><span class="method-icon">◎</span><div><b>攻击面画像</b><p>{html.escape(surface_summary)}</p></div></div></section>{authz_section}{incremental_section}
<section class="section" id="findings"><div class="section-head"><div><h2>复核工作区</h2><p>支持 cwe:89、path:Controller、scanner:codeql、priority:70 组合查询；J/K 切换条目</p></div></div><div class="toolbar"><input class="field" id="search" type="search" placeholder="搜索，或输入 cwe:89 / path:src…"><select class="field" id="severity"><option value="all">全部风险等级</option><option value="critical">严重</option><option value="high">高危</option><option value="medium">中危</option><option value="low">低危</option></select><select class="field" id="review-filter"><option value="all">全部复核状态</option><option value="unreviewed">尚未复核</option><option value="confirmed">确认漏洞</option><option value="false-positive">误报</option><option value="uncertain">仍不确定</option></select><select class="field" id="view-mode" title="切换展示方式"><option value="list">平铺列表</option><option value="by-severity">按严重度</option><option value="by-rule">按规则</option><option value="by-file">按文件</option><option value="by-path">按目录</option><option value="by-scanner">按引擎</option></select><div class="actions"><button class="btn" id="clear" title="清空本地复核">清空</button></div></div><div class="list-meta"><span>显示 <b id="visible-count">{total}</b> / {total} 条</span><span class="progress"><span>复核进度 <b id="review-count">{reviewed_start}</b> / {total}</span><i class="progress-track"><i class="progress-bar" id="progress-bar"></i></i></span></div><div id="finding-list">{cards}</div></section>
<footer>Java Audit Lab {__version__} · 本地离线报告 · 证据先于结论</footer>
</div></main></div>
<script>
const storageKey='java-audit-review:'+document.querySelector('main').dataset.report.split(':')[0],imported={initial_json},state=Object.assign({{}},imported,JSON.parse(localStorage.getItem(storageKey)||'{{}}')),cards=[...document.querySelectorAll('.finding')];
const save=()=>localStorage.setItem(storageKey,JSON.stringify(state));
const RING_C=188.5;
function updateProgress(){{const reviewed=cards.filter(c=>state[c.dataset.fp]?.verdict).length;document.querySelector('#review-count').textContent=reviewed;document.querySelector('#progress-bar').style.width=(cards.length?reviewed/cards.length*100:0)+'%';const pct=cards.length?Math.round(reviewed/cards.length*100):0;const ring=document.querySelector('#ring-fg');if(ring){{ring.style.strokeDashoffset=(RING_C-RING_C*pct/100);document.querySelector('#ring-text').textContent=pct+'%';document.querySelector('#ring-count').textContent=reviewed+' / '+cards.length}}}}
function matchesQuery(c,q){{if(!q)return true;return q.split(/\\s+/).every(token=>{{const parts=token.split(':',2);if(parts.length<2)return c.dataset.search.includes(token);const [key,value]=parts;if(key==='cwe')return c.dataset.cwe.includes(value);if(key==='path')return c.dataset.path.includes(value);if(key==='scanner')return c.dataset.scanner.includes(value);if(key==='priority')return Number(c.dataset.priority)>=Number(value||0);return c.dataset.search.includes(token)}})}}
function groupBy(){{const mode=document.querySelector('#view-mode').value,list=document.querySelector('#finding-list');cards.forEach(c=>c.style.display='');if(mode==='list'){{const sorted=cards.slice().sort((a,b)=>Number(b.dataset.priority)-Number(a.dataset.priority)||a.dataset.path.localeCompare(b.dataset.path));list.innerHTML='';sorted.forEach(c=>list.appendChild(c));return}}const groups={{}},order={{'critical':0,'high':1,'medium':2,'low':3,'info':4}};cards.forEach(c=>{{if(c.classList.contains('hidden'))return;let key;if(mode==='by-severity')key=c.dataset.severity;else if(mode==='by-rule')key=c.dataset.cwe;else if(mode==='by-file'){{const p=c.dataset.path,i=p.lastIndexOf('/');key=i<0?p:p.substring(i+1)}}else if(mode==='by-path'){{const p=c.dataset.path,i=p.indexOf('/');key=i<0?'(root)':p.substring(0,i)}}else if(mode==='by-scanner'){{key=c.dataset.scanner.split(' + ')[0]||'unknown'}};(groups[key]=groups[key]||[]).push(c)}});list.innerHTML='';const keys=Object.keys(groups);if(mode==='by-severity')keys.sort((a,b)=>(order[a]??9)-(order[b]??9));else keys.sort();keys.forEach(key=>{{const h=document.createElement('div'),label=document.createElement('span'),meta=document.createElement('span'),button=document.createElement('button');h.className='group-header';label.textContent=key;meta.className='group-meta';meta.textContent=groups[key].length+' 条';button.className='group-btn';button.textContent='折叠';button.onclick=()=>{{const collapsed=h.dataset.collapsed==='true';h.dataset.collapsed=String(!collapsed);groups[key].forEach(c=>c.style.display=collapsed?'':'none');button.textContent=collapsed?'折叠':'展开'}};h.append(label,meta,button);list.appendChild(h);groups[key].forEach(c=>list.appendChild(c))}})}}
function applyFilters(){{const q=document.querySelector('#search').value.trim().toLowerCase(),sev=document.querySelector('#severity').value,status=document.querySelector('#review-filter').value;let visible=0;cards.forEach(c=>{{const verdict=state[c.dataset.fp]?.verdict||'unreviewed',show=matchesQuery(c,q)&&(sev==='all'||c.dataset.severity===sev)&&(status==='all'||verdict===status);c.classList.toggle('hidden',!show);if(show)visible++}});document.querySelector('#visible-count').textContent=visible;groupBy()}}
cards.forEach(card=>{{const fp=card.dataset.fp;state[fp]=state[fp]||{{}};state[fp].answers=state[fp].answers||{{}};const apply=()=>{{const verdict=state[fp].verdict||'unreviewed',labels={{unreviewed:'尚未复核',confirmed:'已确认漏洞','false-positive':'已标记误报',uncertain:'仍不确定'}};card.dataset.status=verdict;card.querySelectorAll('[data-verdict]').forEach(b=>b.classList.toggle('active',verdict===b.dataset.verdict));card.querySelectorAll('[data-question]').forEach(b=>b.classList.toggle('active',state[fp].answers[b.dataset.question]===b.dataset.answer));card.querySelector('textarea').value=state[fp].notes||'';card.querySelector('[data-confidence]').value=state[fp].confidence||50;card.querySelector('[data-confidence-value]').textContent=(state[fp].confidence||50)+'%';const badge=card.querySelector('[data-review-state]');if(badge)badge.textContent=labels[verdict]||verdict;updateProgress();applyFilters()}};apply();card.querySelectorAll('[data-question]').forEach(b=>b.onclick=()=>{{state[fp].answers[b.dataset.question]=b.dataset.answer;state[fp].updatedAt=new Date().toISOString();save();apply()}});card.querySelectorAll('[data-verdict]').forEach(b=>b.onclick=()=>{{state[fp].verdict=b.dataset.verdict;state[fp].updatedAt=new Date().toISOString();save();apply()}});card.querySelector('textarea').oninput=e=>{{state[fp].notes=e.target.value;save()}};card.querySelector('[data-confidence]').oninput=e=>{{state[fp].confidence=e.target.value;state[fp].updatedAt=new Date().toISOString();save();apply()}}}});
['search','severity','review-filter','view-mode'].forEach(id=>document.querySelector('#'+id).addEventListener('input',applyFilters));
const authzSearch=document.querySelector('#authz-search'),authzFilter=document.querySelector('#authz-filter'),authzRows=[...document.querySelectorAll('[data-authz-status]')];
function applyAuthzFilters(){{if(!authzSearch||!authzFilter)return;const q=authzSearch.value.trim().toLowerCase(),filter=authzFilter.value;let visible=0;authzRows.forEach(row=>{{const statusMatch=filter==='all'||row.dataset.authzStatus===filter||(filter==='anonymous'&&row.dataset.authzRequirement==='anonymous'),show=statusMatch&&(!q||row.dataset.authzSearch.includes(q));row.hidden=!show;if(show)visible++}});const count=document.querySelector('#authz-visible');if(count)count.textContent=visible}}
if(authzSearch&&authzFilter){{authzSearch.addEventListener('input',applyAuthzFilters);authzFilter.addEventListener('input',applyAuthzFilters)}}
document.querySelector('#export').onclick=()=>{{const blob=new Blob([JSON.stringify({{schema_version:'1.3',project:{project_json},exported_at:new Date().toISOString(),reviews:state}},null,2)],{{type:'application/json'}}),a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='review.json';a.click();URL.revokeObjectURL(a.href)}};
document.querySelector('#clear').onclick=()=>{{if(confirm('确定清空当前项目保存在浏览器中的复核记录？')){{localStorage.removeItem(storageKey);location.reload()}}}};
const themeKey='java-audit-theme',root=document.documentElement;root.dataset.theme=localStorage.getItem(themeKey)||'light';
const syncThemeUi=()=>{{const dark=root.dataset.theme==='dark';document.querySelectorAll('[data-theme-label]').forEach(el=>el.textContent=dark?'浅色模式':'深色模式');document.querySelectorAll('.theme-icon').forEach(el=>el.textContent=dark?'☀':'☾');const mobile=document.querySelector('#theme-m');if(mobile)mobile.textContent=dark?'☀':'◐'}};
const toggleTheme=()=>{{root.dataset.theme=root.dataset.theme==='dark'?'light':'dark';localStorage.setItem(themeKey,root.dataset.theme);syncThemeUi()}};
document.querySelector('#theme').onclick=toggleTheme;const tm=document.querySelector('#theme-m');if(tm)tm.onclick=toggleTheme;syncThemeUi();
const navLinks=[...document.querySelectorAll('.side-link')];const spy=new IntersectionObserver(entries=>entries.forEach(e=>{{if(e.isIntersecting)navLinks.forEach(l=>l.classList.toggle('active',l.getAttribute('href')==='#'+e.target.id))}}),{{rootMargin:'-35% 0px -58% 0px'}});{spy_ids}.forEach(id=>{{const el=document.getElementById(id);if(el)spy.observe(el)}});
document.querySelectorAll('[data-copy]').forEach(b=>b.onclick=async()=>{{await navigator.clipboard.writeText(b.dataset.copy);const old=b.textContent;b.textContent='已复制';setTimeout(()=>b.textContent=old,900)}});
document.addEventListener('keydown',e=>{{if(['INPUT','TEXTAREA','SELECT'].includes(document.activeElement.tagName))return;if(!['j','k'].includes(e.key))return;const visible=cards.filter(c=>!c.classList.contains('hidden')),current=visible.findIndex(c=>c===document.activeElement||c.contains(document.activeElement)),next=e.key==='j'?Math.min(visible.length-1,current+1):Math.max(0,current<0?0:current-1);visible[next]?.focus();visible[next]?.scrollIntoView({{behavior:'smooth',block:'center'}})}});
updateProgress();applyFilters();
{js_modal_block}
</script></body></html>'''


_PLAYBOOK_STATUS = {
    "completed": ("已完成", "var(--ok)"),
    "partial": ("部分完成", "var(--medium)"),
    "pending": ("未开始", "var(--faint)"),
}


def _scanner_card(scanner: dict[str, Any]) -> str:
    if scanner["success"]:
        label, color = "已完成", "var(--ok)"
    elif not scanner["available"]:
        label, color = "未安装", "var(--faint)"
    else:
        label, color = "需要处理", "var(--medium)"
    return (
        f'<article class="scanner"><div class="scanner-top"><div><div class="scanner-name">{html.escape(scanner["name"])}</div>'
        f'<span class="scanner-status" style="--status:{color}"><i></i>{label}</span></div>'
        f'<span class="scanner-count">{scanner["finding_count"]}</span></div>'
        f'<p>{html.escape(scanner["message"])}</p></article>'
    )


def _stage_stepper(stages: list[dict[str, Any]]) -> str:
    def _card(stage: dict[str, Any]) -> str:
        status = str(stage.get("status", "pending"))
        label, color = _PLAYBOOK_STATUS.get(status, ("未知", "var(--faint)"))
        evidence_items = "".join(f"<li>{html.escape(str(item))}</li>" for item in stage.get("evidence", [])[:6])
        missing_items = "".join(f"<li>{html.escape(str(item))}</li>" for item in stage.get("missing", [])[:6])
        detail = (
            f'<div class="detail-body"><p style="margin:0 0 6px;color:var(--muted);font-size:12px">{html.escape(str(stage.get("goal", "")))}</p>'
            f'<ul style="margin:0;padding-left:16px;font-size:12px;color:var(--muted)">{evidence_items}</ul>'
        )
        if missing_items:
            detail += f"<li style='color:var(--medium)'>缺口：{'；'.join(html.escape(str(m)) for m in stage.get('missing', [])[:4])}</li>"
        detail += "</ul></div>"
        return (
            f'<article class="scanner" style="--step-color:{color}"><div class="scanner-top"><div>'
            f'<div class="scanner-name">{html.escape(str(stage.get("name", "")))}</div>'
            f'<span class="scanner-status" style="--status:{color}"><i></i>{label}</span>'
            f'</div></div><details style="margin-top:6px"><summary style="cursor:pointer;font-size:12px;color:var(--muted)">阶段证据</summary>{detail}</details></article>'
        )
    return "".join(_card(s) for s in stages)


def _surface_summary(surface: dict[str, Any]) -> str:
    entries = surface.get("entries") or []
    if not entries:
        return "未发现显式入口。若项目为 Web/服务端应用，请人工确认入口写法是否在收集模型内。"
    grouped: dict[str, int] = {}
    for entry in entries:
        kind = str(entry.get("kind", "unknown"))
        grouped[kind] = grouped.get(kind, 0) + 1
    parts = [f"{kind} × {count}" for kind, count in sorted(grouped.items())]
    text = f"共 {len(entries)} 个入口候选：{'，'.join(parts)}"
    controls = surface.get("control_count", 0)
    if controls:
        text += f"；{controls} 个安全控制信号（用于反证检查）"
    dynamics = surface.get("dynamic_calls") or []
    if dynamics:
        text += f"；{len(dynamics)} 处反射/动态调用无法静态解析"
    return text


def _flow_graph(trace: list[dict[str, Any]]) -> str:
    if not trace:
        return ""
    kind_names = {
        "source-candidate": "输入候选",
        "parameter-candidate": "参数入口",
        "propagation-candidate": "传播步骤",
        "flow": "数据流",
        "sink": "危险终点",
    }
    nodes: list[str] = []
    for index, step in enumerate(trace):
        kind = str(step.get("kind", ""))
        label = kind_names.get(kind, "路径步骤")
        step_label = str(step.get("label", ""))
        line = step.get("line", "")
        nodes.append(
            f'<div class="flow-node"><b>{html.escape(label)} · L{line}</b><span>{html.escape(step_label[:120])}</span></div>'
        )
        if index < len(trace) - 1:
            nodes.append('<span class="flow-arrow">→</span>')
    return f'<div class="flow-graph">{"".join(nodes)}</div>'


def _guide_panel() -> str:
    rows = "".join(
        f'<div class="guide-row"><p>{index}. {text}</p><div class="answers">'
        + "".join(f'<button class="answer" data-question="{key}" data-answer="{ans}">{ans}</button>' for ans in labels)
        + '</div></div>'
        for index, (key, text, labels) in enumerate(FIVE_QUESTIONS, start=1)
    )
    return f'<div class="guide"><div class="guide-head"><b>漏洞成立五问</b><span>全部回答后再给出最终结论</span></div>{rows}</div>'


def _incremental_section(payload: dict[str, Any]) -> str:
    """阶段 C-1：Git 增量审计章节。全量扫描时不渲染。"""
    data = payload.get("incremental") or {}
    if not data.get("enabled"):
        return ""
    stats = data.get("stats") or {}
    mode_labels = {"working": "工作区未提交变更", "ref": "与指定分支比较", "commit": "单次提交"}
    mode_text = mode_labels.get(str(data.get("mode", "")), str(data.get("mode", "")))
    chips = "".join(
        f'<span style="font-size:11px;color:var(--muted);background:var(--surface);border:1px solid var(--line);border-radius:20px;padding:3px 10px">{label} <b style="color:var(--ink)">{stats.get(key, 0)}</b></span>'
        for label, key in (("变更文件", "files_changed"), ("Java 变更", "java_files_changed"),
                           ("新增文件", "files_added"), ("删除文件", "files_deleted"),
                           ("依赖闭包", "closure_files"), ("变更行", "lines_changed"))
    )
    focus_items = "".join(
        f'<li style="margin-bottom:5px">{html.escape(str(item))}</li>' for item in (data.get("review_focus") or [])
    )
    focus_block = (
        f'<div style="margin-bottom:14px;padding:12px 14px;border:1px solid color-mix(in srgb,var(--brand) 32%,var(--line));'
        f'background:var(--brand-soft);border-radius:11px;font-size:12.5px;color:var(--ink)">'
        f'<b style="color:var(--brand-ink)">本轮复核焦点</b><ul style="margin:7px 0 0;padding-left:18px">{focus_items}</ul></div>'
        if focus_items else ""
    )

    # 权限声明变化
    risk_colors = {"high": "var(--critical)", "medium": "var(--medium)", "review": "var(--brand)", "info": "var(--muted)"}
    change_labels = {"weakened": "放宽", "strengthened": "收紧", "added": "新增端点", "removed": "移除端点", "role_changed": "角色变化"}
    authz_rows = []
    for item in data.get("authz_changes") or []:
        change = str(item.get("change", ""))
        risk = str(item.get("risk", "info"))
        old_roles = ", ".join(str(x) for x in (item.get("old_roles") or [])) or "—"
        new_roles = ", ".join(str(x) for x in (item.get("new_roles") or [])) or "—"
        authz_rows.append(
            f'<tr>'
            f'<td><code style="color:var(--brand-ink)">{html.escape(str(item.get("route", "")))}</code>'
            f'<div style="font-size:11px;color:var(--faint)">{html.escape(str(item.get("method", "")))}</div></td>'
            f'<td><span style="color:{risk_colors.get(risk, "var(--muted)")};font-weight:700">{html.escape(change_labels.get(change, change))}</span></td>'
            f'<td>{html.escape(old_roles)}</td><td>{html.escape(new_roles)}</td>'
            f'<td style="font-size:11.5px;color:var(--muted)">{html.escape(str(item.get("detail", "")))}</td>'
            f'</tr>'
        )
    authz_table = (
        '<div class="card" style="overflow-x:auto;margin-bottom:14px">'
        '<div style="padding:12px 14px 6px;font-size:12.5px;font-weight:700">权限声明变化'
        '<span style="font-weight:400;color:var(--muted);font-size:11.5px"> · 对比本次变更前后的端点权限声明</span></div>'
        '<table style="width:100%;border-collapse:collapse;font-size:12px">'
        '<thead><tr style="text-align:left">'
        '<th style="padding:8px 14px;border-bottom:1px solid var(--line);font-size:11px;color:var(--muted)">接口</th>'
        '<th style="padding:8px 14px;border-bottom:1px solid var(--line);font-size:11px;color:var(--muted)">变化</th>'
        '<th style="padding:8px 14px;border-bottom:1px solid var(--line);font-size:11px;color:var(--muted)">原角色/权限</th>'
        '<th style="padding:8px 14px;border-bottom:1px solid var(--line);font-size:11px;color:var(--muted)">现角色/权限</th>'
        '<th style="padding:8px 14px;border-bottom:1px solid var(--line);font-size:11px;color:var(--muted)">说明</th>'
        '</tr></thead><tbody>' + "".join(authz_rows) + "</tbody></table></div>"
        if authz_rows else ""
    )

    # 本次变更引入的发现
    severity_colors = {"critical": "var(--critical)", "high": "var(--high)", "medium": "var(--medium)", "low": "var(--low)", "info": "var(--muted)"}
    variant_set = {str(item.get("rule_id")) + str(item.get("line")) for item in (data.get("variant_findings") or [])}
    finding_rows = []
    for item in data.get("new_findings") or []:
        severity = str(item.get("severity", "medium"))
        marker = "同类新位置" if (str(item.get("rule_id")) + str(item.get("line"))) in variant_set else ""
        endpoint = str(item.get("endpoint") or "")
        finding_rows.append(
            f'<tr>'
            f'<td><code style="color:var(--brand-ink)">{html.escape(str(item.get("rule_id", "")))}</code>'
            f'<div style="font-size:11px;color:var(--faint)">{html.escape(str(item.get("cwe", "")))}</div></td>'
            f'<td><span style="color:{severity_colors.get(severity, "var(--medium)")};font-weight:700">{html.escape(severity)}</span></td>'
            f'<td style="font-size:11.5px">{html.escape(str(item.get("path", "")))}:{item.get("line", 0)}</td>'
            f'<td style="font-size:11.5px;color:var(--muted)">{html.escape(endpoint or "—")}</td>'
            f'<td style="font-size:11.5px;color:var(--muted)">{html.escape(marker)}</td>'
            f'</tr>'
        )
    findings_table = (
        '<div class="card" style="overflow-x:auto;margin-bottom:14px">'
        '<div style="padding:12px 14px 6px;font-size:12.5px;font-weight:700">本次变更引入的发现'
        f'<span style="font-weight:400;color:var(--muted);font-size:11.5px"> · 共 {len(finding_rows)} 条</span></div>'
        '<table style="width:100%;border-collapse:collapse;font-size:12px">'
        '<thead><tr style="text-align:left">'
        '<th style="padding:8px 14px;border-bottom:1px solid var(--line);font-size:11px;color:var(--muted)">规则</th>'
        '<th style="padding:8px 14px;border-bottom:1px solid var(--line);font-size:11px;color:var(--muted)">严重度</th>'
        '<th style="padding:8px 14px;border-bottom:1px solid var(--line);font-size:11px;color:var(--muted)">位置</th>'
        '<th style="padding:8px 14px;border-bottom:1px solid var(--line);font-size:11px;color:var(--muted)">所属端点</th>'
        '<th style="padding:8px 14px;border-bottom:1px solid var(--line);font-size:11px;color:var(--muted)">备注</th>'
        '</tr></thead><tbody>' + "".join(finding_rows) + "</tbody></table></div>"
        if finding_rows else '<div class="card" style="padding:22px;text-align:center;color:var(--muted);font-size:12.5px;margin-bottom:14px">本次变更未引入新的发现。</div>'
    )

    # 修复验证
    fixed_rows = []
    for item in data.get("fixed_findings") or []:
        unresolved = str(item.get("status", "")) == "疑似未真正修复"
        fixed_rows.append(
            f'<tr><td><code style="color:var(--brand-ink)">{html.escape(str(item.get("rule_id", "")))}</code></td>'
            f'<td style="font-size:11.5px">{html.escape(str(item.get("path", "")))}:{item.get("line", 0)}</td>'
            f'<td><span style="color:{"var(--critical)" if unresolved else "var(--ok)"};font-weight:700">{html.escape(str(item.get("status", "")))}</span></td>'
            f'<td style="font-size:11.5px;color:var(--muted)">{html.escape(str(item.get("note", "")))}</td></tr>'
        )
    fixed_table = (
        '<div class="card" style="overflow-x:auto;margin-bottom:14px">'
        '<div style="padding:12px 14px 6px;font-size:12.5px;font-weight:700">修复验证'
        '<span style="font-weight:400;color:var(--muted);font-size:11.5px"> · 基线中消失的命中是否真正切断路径</span></div>'
        '<table style="width:100%;border-collapse:collapse;font-size:12px">'
        '<thead><tr style="text-align:left">'
        '<th style="padding:8px 14px;border-bottom:1px solid var(--line);font-size:11px;color:var(--muted)">规则</th>'
        '<th style="padding:8px 14px;border-bottom:1px solid var(--line);font-size:11px;color:var(--muted)">原位置</th>'
        '<th style="padding:8px 14px;border-bottom:1px solid var(--line);font-size:11px;color:var(--muted)">状态</th>'
        '<th style="padding:8px 14px;border-bottom:1px solid var(--line);font-size:11px;color:var(--muted)">说明</th>'
        '</tr></thead><tbody>' + "".join(fixed_rows) + "</tbody></table></div>"
        if fixed_rows else ""
    )

    notes = "".join(f'<li style="margin-bottom:4px">{html.escape(str(item))}</li>' for item in (data.get("notes") or []))
    notes_block = (
        f'<div style="padding:11px 13px;border:1px dashed var(--line);border-radius:11px;font-size:11.5px;color:var(--muted)">'
        f'<b>说明</b><ul style="margin:6px 0 0;padding-left:18px">{notes}</ul></div>' if notes else ""
    )
    return (
        '<section class="section" id="incremental"><div class="section-head"><div><h2>Git 增量审计</h2>'
        f'<p>{html.escape(mode_text)} · 基准 <code>{html.escape(str(data.get("base", "")))}</code> · 只分析变更文件与依赖闭包</p></div>'
        f'<div style="display:flex;flex-wrap:wrap;gap:6px">{chips}</div></div>'
        f'{focus_block}{authz_table}{findings_table}{fixed_table}{notes_block}</section>'
    )


def _engagement_section(payload: dict[str, Any]) -> str:
    """Professional scope record derived from local evidence and optional project config."""
    project = payload.get("project") or {}
    engagement = payload.get("engagement") or {}
    inventory = project.get("inventory") or {}
    scanners = payload.get("scanners") or []
    completed = sum(1 for scanner in scanners if scanner.get("success"))
    unavailable = sum(1 for scanner in scanners if not scanner.get("available"))
    revision = str(project.get("revision") or "未检测到 Git 提交")
    branch = str(project.get("branch") or "未检测到分支")
    snapshot = f"{branch} · {revision}" if project.get("revision") else revision
    generated = str(payload.get("generated_at", "")).replace("T", " ").replace("+00:00", " UTC")[:23]
    by_extension = inventory.get("by_extension") or {}
    extensions = "".join(
        f'<span>{html.escape(str(suffix))} × {int(count)}</span>'
        for suffix, count in list(by_extension.items())[:10]
    ) or '<span>未采集扩展名统计</span>'
    excluded = engagement.get("excluded_paths") or []
    excluded_text = "、".join(str(item) for item in excluded) if excluded else "未配置额外排除路径"
    return (
        '<section class="section" id="engagement"><div class="section-head"><div><h2>审计档案与范围</h2>'
        '<p>记录本次扫描对象、代码快照、覆盖范围与报告适用边界，便于复核和后续重扫</p></div></div>'
        '<div class="dossier-grid">'
        f'<article class="dossier-card"><span>报告负责人</span><b title="{html.escape(str(engagement.get("report_owner", "未填写")))}">{html.escape(str(engagement.get("report_owner", "未填写")))}</b><small>可在项目配置中填写 report_owner</small></article>'
        f'<article class="dossier-card"><span>代码快照</span><b title="{html.escape(snapshot)}">{html.escape(snapshot)}</b><small>用于区分代码迭代前后的审计结果</small></article>'
        f'<article class="dossier-card"><span>扫描器覆盖</span><b>{completed} / {len(scanners)} 已完成</b><small>{unavailable} 个扫描器未安装或不可用</small></article>'
        f'<article class="dossier-card"><span>生成时间</span><b>{html.escape(generated)}</b><small>工具版本 Java Audit Lab {html.escape(str(payload.get("tool", {}).get("version", "")))}</small></article>'
        '</div><div class="scope-sheet"><div class="scope-block"><h3>扫描覆盖清单</h3><div class="scope-list">'
        f'<div class="scope-item"><span>项目文件</span><b>{int(inventory.get("total_files", 0))}</b></div>'
        f'<div class="scope-item"><span>源代码文件</span><b>{int(inventory.get("source_files", project.get("java_files", 0)))}</b></div>'
        f'<div class="scope-item"><span>配置文件</span><b>{int(inventory.get("config_files", 0))}</b></div>'
        f'<div class="scope-item"><span>Web 前端文件</span><b>{int(inventory.get("web_files", 0))}</b></div>'
        f'<div class="scope-item"><span>估算文本行数</span><b>{int(inventory.get("estimated_lines", 0)):,}</b></div>'
        f'<div class="scope-item"><span>入口候选</span><b>{int((payload.get("surface") or {}).get("entry_count", 0))}</b></div>'
        f'</div><div class="extension-list">{extensions}</div></div>'
        '<div class="scope-block"><h3>范围与使用边界</h3><div class="scope-copy">'
        f'<div><b>扫描范围</b><span>{html.escape(str(engagement.get("scope_note", project.get("root", ""))))}</span></div>'
        f'<div><b>授权依据</b><span>{html.escape(str(engagement.get("authorization_ref", "未填写；授权状态由使用者自行确认")))}</span></div>'
        f'<div><b>排除路径</b><span>{html.escape(excluded_text)}</span></div>'
        f'<div><b>报告有效性</b><span>{html.escape(str(engagement.get("validity_note", "代码、配置或依赖变化后应重新扫描。")))}</span></div>'
        f'<div><b>数据保留</b><span>{html.escape(str(engagement.get("retention_note", "公开报告前检查敏感信息。")))}</span></div>'
        '</div></div></div></section>'
    )


def _authz_section(payload: dict[str, Any]) -> str:
    """阶段 B：端点 × 身份要求 × 角色 × 危险操作 × 证据状态 矩阵。"""
    authz = payload.get("authz") or {}
    endpoints = authz.get("endpoints") or []
    coverage = authz.get("coverage") or {}
    if not endpoints:
        return (
            '<section class="section" id="authz"><div class="section-head"><div><h2>端点权限矩阵</h2>'
            '<p>接口 × 身份要求 × 角色 × 危险操作 × 证据状态</p></div></div>'
            '<div class="card" style="padding:30px 20px;text-align:center;color:var(--muted);font-size:12.5px">'
            '未识别到 HTTP 端点：项目可能不是 Web 服务，或路由写法不在当前模型内（Spring MVC / JAX-RS）。'
            '</div></section>'
        )
    requirement_colors = {
        "anonymous": "var(--critical)", "authenticated": "var(--brand)",
        "role": "var(--ok)", "permission": "var(--ok)", "ownership": "var(--cyan)", "unknown": "var(--medium)",
    }
    requirement_labels = {
        "anonymous": "无需登录", "authenticated": "需登录", "role": "需角色",
        "permission": "需权限", "ownership": "需数据归属", "unknown": "未知",
    }
    status_colors = {"proven": "var(--ok)", "inferred": "var(--medium)", "missing": "var(--critical)"}
    status_labels = {"proven": "权限已证明", "inferred": "权限推测", "missing": "权限缺失"}
    rows = []
    for endpoint in endpoints:
        requirement = str(endpoint.get("requirement", "unknown"))
        status = str(endpoint.get("status", "missing"))
        roles = endpoint.get("roles") or []
        permissions = endpoint.get("permissions") or []
        role_text = ", ".join(str(item) for item in roles + permissions) or "—"
        ops = endpoint.get("dangerous_ops") or []
        ops_text = ", ".join(str(item) for item in ops[:4]) or "—"
        if len(ops) > 4:
            ops_text += f" +{len(ops) - 4}"
        expression = str(endpoint.get("expression") or "")
        search_text = " ".join([
            str(endpoint.get("route", "")), str(endpoint.get("handler", "")),
            str(endpoint.get("path", "")), str(endpoint.get("http_method", "")),
            role_text, ops_text, requirement_labels.get(requirement, requirement),
            status_labels.get(status, status),
        ]).lower()
        route = html.escape(str(endpoint.get("route", "")) or "/")
        handler = html.escape(str(endpoint.get("handler", "")))
        source_path = html.escape(str(endpoint.get("path", "")))
        method = html.escape(str(endpoint.get("http_method", "")))
        requirement_label = html.escape(requirement_labels.get(requirement, requirement))
        status_label = html.escape(status_labels.get(status, status))
        rows.append(
            f'<tr data-authz-status="{html.escape(status)}" data-authz-requirement="{html.escape(requirement)}" data-authz-search="{html.escape(search_text)}">'
            f'<td title="{handler} · {source_path}:{endpoint.get("line", 0)}"><code class="authz-route">{route}</code>'
            f'<span class="authz-meta">{handler} · {source_path}:{endpoint.get("line", 0)}</span></td>'
            f'<td><span class="method-badge">{method}</span></td>'
            f'<td><span class="status-badge" style="--badge-color:{requirement_colors.get(requirement, "var(--medium)")}">{requirement_label}</span></td>'
            f'<td><span class="authz-cell-main" title="{html.escape(role_text)}">{html.escape(role_text)}</span>'
            + (f'<span class="authz-cell-sub" title="{html.escape(expression)}">{html.escape(expression[:120])}</span>' if expression else "")
            + '</td>'
            f'<td><span class="authz-cell-main" title="{html.escape(ops_text)}">{html.escape(ops_text)}</span></td>'
            f'<td><span class="status-badge" style="--badge-color:{status_colors.get(status, "var(--medium)")}">{status_label}</span></td>'
            f'</tr>'
        )
    chips = "".join(
        f'<span class="authz-chip">{label} <b>{coverage.get(key, 0)}</b></span>'
        for label, key in (("端点", "endpoints"), ("权限已证明", "proven"), ("权限缺失", "missing"), ("匿名可访问", "anonymous"), ("配置规则", "rules"))
    )
    high_risk = int(coverage.get("unprotected_high_risk", 0) or 0)
    warning = (
        f'<div style="margin-top:12px;padding:11px 13px;border:1px solid color-mix(in srgb,var(--critical) 30%,var(--line));'
        f'background:var(--critical-soft);border-radius:11px;font-size:12px;color:var(--ink)">'
        f'<b style="color:var(--critical)">{high_risk} 个端点存在危险操作但身份要求为匿名或未知</b>，建议优先人工确认其认证与授权状态。</div>'
        if high_risk else ""
    )
    return (
        '<section class="section" id="authz"><div class="section-head"><div><h2>端点权限矩阵</h2>'
        '<p>证据来源：方法级注解 → 安全配置匹配 → Shiro 过滤链；没有匹配到的端点标记为权限缺失，需人工确认</p></div>'
        f'<div class="authz-summary">{chips}</div></div>'
        '<div class="authz-tools"><div class="authz-filters">'
        '<input class="field" id="authz-search" type="search" placeholder="搜索接口、处理器、角色或危险操作">'
        '<select class="field" id="authz-filter"><option value="all">全部证据状态</option><option value="missing">权限缺失</option><option value="inferred">权限推测</option><option value="proven">权限已证明</option><option value="anonymous">匿名可访问</option></select>'
        f'</div><span class="authz-count">显示 <b id="authz-visible">{len(rows)}</b> / {len(rows)} 个端点</span></div>'
        '<div class="card authz-shell"><div class="authz-scroll">'
        '<table class="authz-table"><colgroup><col style="width:34%"><col style="width:8%"><col style="width:12%"><col style="width:18%"><col style="width:14%"><col style="width:14%"></colgroup>'
        '<thead><tr><th>接口与代码位置</th><th>方法</th><th>身份要求</th><th>角色 / 权限</th><th>危险操作</th><th>证据状态</th>'
        '</tr></thead><tbody>' + "".join(rows) + "</tbody></table></div></div>" + warning + "</section>"
    )


def _finding_card(finding: dict[str, Any], is_new: bool) -> str:
    loc = finding["location"]
    steps = "".join(f"<li>{html.escape(s)}</li>" for s in finding.get("review_steps", []))
    positive = "".join(f"<li>{html.escape(p)}</li>" for p in (finding.get("evidence_for") or []))
    negative = "".join(f"<li>{html.escape(n)}</li>" for n in (finding.get("evidence_against") or []))
    trace = finding.get("trace") or []
    graph = _flow_graph(trace)
    trace_html = "".join(
        f'<li><code>{html.escape(str(s.get("path", "")))}:{s.get("line", 1)}</code><br>{html.escape(str(s.get("label", ""))[:160])}</li>'
        for s in trace
    )
    factors = "".join(
        f'<div class="factor"><b>+{item.get("points", 0)}</b><span>{html.escape(str(item.get("factor", "")))} — {html.escape(str(item.get("reason", "")))}</span></div>'
        for item in finding.get("priority_factors", [])
    )
    scanners = finding.get("metadata", {}).get("scanners") or [finding.get("scanner", "")]
    corroboration = finding.get("metadata", {}).get("corroboration") or []
    corroboration_items = "".join(
        f'<li><b>{html.escape(str(c.get("scanner", "")))}</b> · {html.escape(str(c.get("rule_id", "")))} · 第 {c.get("line", 1)} 行<br>{html.escape(str(c.get("evidence", ""))[:200])}</li>'
        for c in corroboration
    )
    corroboration_block = (
        f'<details><summary>扫描器交叉证据 · {len(corroboration)} 个来源</summary><div class="detail-body"><ol>{corroboration_items}</ol></div></details>'
        if corroboration else ""
    )
    evidence_record = finding.get("metadata", {}).get("evidence_record") or {}

    def _loc_text(rec: dict[str, Any]) -> str:
        if rec.get("path"):
            return f"{rec['path']}:{rec.get('line', 1)}"
        return str(rec.get("label") or "未采集")

    record_block = ""
    if evidence_record:
        source_text = _loc_text(evidence_record.get("source") or {})
        sink_text = _loc_text(evidence_record.get("sink") or {})
        prop_count = len(evidence_record.get("propagation") or [])
        sanitizer_items = "".join(
            f'<li>{html.escape(str(item.get("detail", item))[:160])}</li>'
            for item in evidence_record.get("sanitizers") or []
        ) or "<li>未观察到净化或抑制证据</li>"
        engine_items = "".join(
            f'<li><b>{html.escape(str(item.get("scanner", "")))}</b> · {html.escape(str(item.get("rule_id", "")))}</li>'
            for item in evidence_record.get("engine_evidence") or []
        ) or "<li>仅单一引擎命中</li>"
        entry_rec = evidence_record.get("entry") or {}
        entry_text = "位于已识别入口文件" if entry_rec.get("covered") else str(entry_rec.get("note") or "未关联入口")
        auth_rec = evidence_record.get("authorization") or {}
        unresolved_items = "".join(
            f'<li><code>{html.escape(str(step.get("path", "")))}:{step.get("line", 1)}</code> {html.escape(str(step.get("label", ""))[:120])}</li>'
            for step in evidence_record.get("unresolved_steps") or []
        )
        unresolved_html = f'<div style="grid-column:1/-1"><b style="display:block;font-size:11px;color:var(--muted);margin-bottom:5px">未解析步骤</b><ul style="margin:0;padding-left:16px">{unresolved_items}</ul></div>' if unresolved_items else ""
        conclusion_text = str(evidence_record.get("path_conclusion", ""))
        record_block = (
            f'<details><summary>统一证据记录 · {html.escape(conclusion_text)}</summary><div class="detail-body">'
            f'<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:10px;font-size:12px">'
            f'<div style="padding:9px 11px;background:var(--surface-soft);border-radius:8px"><b style="display:block;font-size:11px;color:var(--muted);margin-bottom:4px">入口</b>{html.escape(entry_text)}</div>'
            f'<div style="padding:9px 11px;background:var(--surface-soft);border-radius:8px"><b style="display:block;font-size:11px;color:var(--muted);margin-bottom:4px">来源</b><code>{html.escape(source_text)}</code></div>'
            f'<div style="padding:9px 11px;background:var(--surface-soft);border-radius:8px"><b style="display:block;font-size:11px;color:var(--muted);margin-bottom:4px">传播</b>{prop_count} 个引擎步骤</div>'
            f'<div style="padding:9px 11px;background:var(--surface-soft);border-radius:8px"><b style="display:block;font-size:11px;color:var(--muted);margin-bottom:4px">终点</b><code>{html.escape(sink_text)}</code></div>'
            f'<div style="padding:9px 11px;background:var(--surface-soft);border-radius:8px"><b style="display:block;font-size:11px;color:var(--muted);margin-bottom:4px">净化/抑制（反证）</b><ul style="margin:0;padding-left:16px">{sanitizer_items}</ul></div>'
            f'<div style="padding:9px 11px;background:var(--surface-soft);border-radius:8px"><b style="display:block;font-size:11px;color:var(--muted);margin-bottom:4px">权限</b>{html.escape(str(auth_rec.get("status", "未采集")))}</div>'
            f'<div style="padding:9px 11px;background:var(--surface-soft);border-radius:8px"><b style="display:block;font-size:11px;color:var(--muted);margin-bottom:4px">引擎佐证</b><ul style="margin:0;padding-left:16px">{engine_items}</ul></div>'
            f'{unresolved_html}'
            f'</div></div></details>'
        )
    ai = finding.get("metadata", {}).get("ai_explanation") or ""
    ai_block = f'<details><summary>AI 分层解释</summary><div class="detail-body"><pre>{html.escape(ai)}</pre></div></details>' if ai else ""
    scanner_text = " + ".join(scanners)
    scope = str(finding.get("metadata", {}).get("scope", "production"))
    scope_labels = {"production": "生产代码", "test": "测试代码", "generated": "生成代码", "example": "示例代码"}
    endpoint_text = str(finding.get("metadata", {}).get("endpoint", "") or "")
    endpoint_tag = f'<span class="tag">{html.escape(endpoint_text)}</span>' if endpoint_text else ""
    search_text = " ".join([
        finding.get("title", ""), finding.get("cwe", ""), finding.get("rule_id", ""),
        str(finding.get("severity", "")), str(finding.get("confidence", "")),
        scanner_text, endpoint_text, scope, scope_labels.get(scope, scope), str(finding.get("description", "")),
        loc.get("path", ""),
    ]).lower()
    guide = _guide_panel()
    location_text = f"{loc['path']}:{loc['line']}"
    assessment = finding.get("metadata", {}).get("path_assessment", {})
    conclusion_labels = {"proven": "已证明路径", "inferred": "推测路径", "missing": "缺失路径", "unresolved": "动态调用未解析"}
    path_label = conclusion_labels.get(str(assessment.get("conclusion", "missing")), "缺失路径")
    generalization = finding.get("metadata", {}).get("generalization") or {}
    sibling_items = "".join(
        f'<li><code>{html.escape(str(item.get("path", "")))}:{item.get("line", 1)}</code></li>'
        for item in generalization.get("same_rule", [])[:20]
    )
    nearby_items = "".join(
        f'<li><code>{html.escape(str(item.get("path", "")))}:{item.get("line", 1)}</code></li>'
        for item in generalization.get("nearby_same_file", [])[:10]
    )
    nearby_block = f'<p style="margin:8px 0 0;font-size:12px;color:var(--muted)">同文件邻近写法：</p><ul style="margin:4px 0 0;padding-left:18px;font-size:12px">{nearby_items}</ul>' if nearby_items else ""
    generalization_block = (
        f'<details><summary>同类模式排查 · 同规则 {generalization.get("same_rule_count", 0)} 处 / 同 CWE 其他规则 {generalization.get("same_cwe_other_rule_count", 0)} 处</summary>'
        f'<div class="detail-body"><p style="margin:0 0 8px;font-size:12px;color:var(--muted)">确认本条后优先复核以下位置：</p>'
        f'<ul style="margin:0 0 8px;padding-left:18px;font-size:12px">{sibling_items}</ul>{nearby_block}</div></details>'
    ) if sibling_items or nearby_items or generalization.get("same_cwe_other_rule_count") else ""
    trace_block = f'<details open><summary>数据流证据 · {len(trace)} 步 · {html.escape(path_label)}</summary><div class="detail-body">{graph}<ol class="trace">{trace_html}</ol></div></details>' if trace else ''
    new_badge = '<span class="tag tag-new">基线新增</span>' if is_new else ''
    return (
        f'<article class="finding" tabindex="0" data-fp="{html.escape(finding["fingerprint"])}" data-severity="{html.escape(finding["severity"])}" data-status="unreviewed" data-search="{html.escape(search_text)}" data-cwe="{html.escape(finding["cwe"].lower())}" data-path="{html.escape(loc["path"].lower())}" data-scanner="{html.escape(scanner_text.lower())}" data-priority="{int(finding.get("review_priority", 0))}">'
        f'<div class="finding-main"><div class="finding-head"><div><div class="finding-kicker">'
        f'<span class="tag tag-risk">{html.escape(finding["severity"].upper())}</span>'
        f'<span class="tag">优先级 {int(finding.get("review_priority", 0))}</span>'
        f'<span class="tag">{html.escape(finding["cwe"])}</span>'
        f'<span class="tag">{html.escape(" + ".join(scanners))}</span>'
        f'<span class="tag">{html.escape(scope_labels.get(scope, scope))}</span>'
        f'{endpoint_tag}'
        f'<span class="tag">置信度 {html.escape(finding["confidence"])}</span>'
        f'<span class="tag">{html.escape(path_label)}</span>'
        f'{new_badge}'
        f'</div><h3>{html.escape(finding["title"])}</h3></div>'
        f'<button class="location" data-copy="{html.escape(location_text)}" title="复制代码位置">{html.escape(location_text)}</button></div>'
        f'<p class="description">{html.escape(finding["description"])}</p>'
        f'<pre>{html.escape(finding["evidence"])}</pre></div>'
        f'<details><summary>为什么优先复核 · {int(finding.get("review_priority", 0))}/100</summary><div class="detail-body"><div class="priority-explain">{factors}</div></div></details>'
        f'{trace_block}'
        f'{generalization_block}{corroboration_block}{record_block}'
        f'<details open><summary>可证伪检查</summary><div class="detail-body"><div class="gate"><div class="gate-panel positive"><b>支持漏洞假设</b><ul>{positive}</ul></div><div class="gate-panel negative"><b>能够推翻假设</b><ul>{negative}</ul></div></div></div></details>'
        f'{guide}'
        f'<details><summary>人工复核步骤</summary><div class="detail-body"><ol>{steps}</ol></div></details>'
        f'<details><summary>学习提示与修复方向</summary><div class="detail-body"><p>{html.escape(finding.get("learning_note", ""))}</p><p>{html.escape(finding["remediation"])}</p></div></details>'
        f'{ai_block}'
        f'<div class="review"><div class="review-head"><div><b>人工复核记录</b><small>用于记录你的最终判断；内容只保存在当前浏览器，点击“导出复核”可备份。</small></div><span class="review-state" data-review-state>尚未复核</span></div>'
        f'<div class="review-grid"><div class="review-decision"><div><span class="review-label">复核结论</span><div class="verdicts"><button class="verdict" data-verdict="confirmed">确认漏洞</button><button class="verdict" data-verdict="false-positive">标记误报</button><button class="verdict" data-verdict="uncertain">仍不确定</button></div></div>'
        f'<label class="confidence"><span>判断信心</span><b data-confidence-value>50%</b><input data-confidence type="range" min="0" max="100" value="50"></label></div>'
        f'<label class="review-notes"><span>复核备注</span><textarea placeholder="记录支持证据、反证条件和仍未回答的问题…"></textarea></label></div></div>'
        f'</article>'
    )


def _render_markdown(payload: dict[str, Any]) -> str:
    """Stage 5 audit report: evidence-first Markdown. No attack payloads, no authorization claims."""
    project, summary, surface = payload["project"], payload["summary"], payload.get("surface") or {}
    engagement = payload.get("engagement") or {}
    playbook_data = payload.get("playbook") or {}
    baseline = payload["baseline"]
    findings = payload["findings"]
    lines: list[str] = []
    lines.append(f"# Java Audit Lab 审计报告 · {project['name']}")
    lines.append("")
    lines.append(f"- 工具版本：Java Audit Lab {payload['tool']['version']}（Evidence Driven Audit Playbook）")
    lines.append(f"- 生成时间：{payload['generated_at']}")
    lines.append(f"- 扫描范围：{project['root']}")
    lines.append(f"- 报告负责人：{engagement.get('report_owner', '未填写')}")
    lines.append(f"- 授权依据：{engagement.get('authorization_ref', '未填写；授权状态由使用者自行确认')}")
    lines.append(f"- 结论性质：{payload['disclaimer']}")
    lines.append("")
    lines.append("## 一、执行摘要")
    lines.append("")
    counts = summary["by_severity"]
    lines.append("| 等级 | 数量 |")
    lines.append("|---|---|")
    for level in ("critical", "high", "medium", "low", "info"):
        label = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "提示"}[level]
        lines.append(f"| {label} | {counts.get(level, 0)} |")
    lines.append("")
    lines.append(f"共 {summary['total']} 条待复核线索，已人工复核 {summary['reviewed']} 条。")
    if baseline.get("enabled"):
        lines.append(f"基线对比：新增 {len(baseline.get('new', []))} 条，已有 {len(baseline.get('existing', []))} 条，已修复 {len(baseline.get('fixed', []))} 条。")
    lines.append("")
    lines.append("### 技术栈与攻击面画像")
    lines.append("")
    frameworks = ", ".join(project.get("frameworks", [])) or "未识别常见框架"
    lines.append(f"- 构建系统：{project['build_system']}（{', '.join(project['manifests']) or '无构建清单'}）")
    lines.append(f"- 框架：{frameworks}")
    lines.append(f"- Java 源文件：{project['java_files']} 个")
    entries = surface.get("entries", [])
    if entries:
        grouped: dict[str, list] = {}
        for entry in entries:
            grouped.setdefault(str(entry.get("kind", "unknown")), []).append(entry)
        lines.append(f"- 入口候选：共 {len(entries)} 个")
        for kind, items in sorted(grouped.items()):
            lines.append(f"  - {kind} × {len(items)}")
            for item in items[:8]:
                route = f" `{item.get('http_method', '')} {item.get('route')}`" if item.get("route") else ""
                lines.append(f"    - {item.get('path')}:{item.get('line')}{route}")
            if len(items) > 8:
                lines.append(f"    - ……其余 {len(items) - 8} 处见 report.json")
    else:
        lines.append("- 入口候选：未发现显式入口（人工确认入口写法是否在收集模型内）")
    controls = surface.get("controls", [])
    if controls:
        kinds = sorted({str(item.get("kind")) for item in controls})
        lines.append(f"- 安全控制信号（反证证据）：{len(controls)} 个（{'、'.join(kinds)}）")
    dynamics = surface.get("dynamic_calls", [])
    if dynamics:
        lines.append(f"- ⚠ 无法静态解析的动态调用：{len(dynamics)} 处，需要人工确认调用目标")
    lines.append("")
    lines.append("### 审计阶段完成度")
    lines.append("")
    lines.append("| 阶段 | 状态 | 证据 | 缺口 |")
    lines.append("|---|---|---|---|")
    status_labels = {"completed": "已完成", "partial": "部分完成", "pending": "未开始"}
    for stage in playbook_data.get("stages", []):
        status = status_labels.get(str(stage.get("status")), str(stage.get("status")))
        evidence = "；".join(str(item) for item in stage.get("evidence", [])[:4])
        missing = "；".join(str(item) for item in stage.get("missing", [])[:4])
        lines.append(f"| {stage.get('name')} | {status} | {evidence or '—'} | {missing or '—'} |")
    lines.append("")
    section_labels = ["一", "二", "三", "四", "五", "六", "七", "八", "九", "十"]
    section_index = 1

    def add_section(title: str) -> None:
        nonlocal section_index
        label = section_labels[section_index] if section_index < len(section_labels) else str(section_index + 1)
        lines.append(f"## {label}、{title}")
        section_index += 1

    add_section("审计档案与范围")
    lines.append("")
    inventory = project.get("inventory") or {}
    snapshot = f"{project.get('branch') or '未检测到分支'} · {project.get('revision') or '未检测到 Git 提交'}"
    lines.append("| 字段 | 记录 |")
    lines.append("|---|---|")
    lines.append(f"| 代码快照 | {snapshot} |")
    lines.append(f"| 扫描范围 | {engagement.get('scope_note', project.get('root', ''))} |")
    lines.append(f"| 排除路径 | {'、'.join(str(item) for item in engagement.get('excluded_paths', [])) or '未配置额外排除路径'} |")
    lines.append(f"| 项目文件 | {inventory.get('total_files', 0)} 个 |")
    lines.append(f"| 源代码文件 | {inventory.get('source_files', project.get('java_files', 0))} 个 |")
    lines.append(f"| 配置文件 | {inventory.get('config_files', 0)} 个 |")
    lines.append(f"| Web 前端文件 | {inventory.get('web_files', 0)} 个 |")
    lines.append(f"| 估算文本行数 | {inventory.get('estimated_lines', 0)} 行（统计 {inventory.get('line_counted_files', 0)} 个文本文件） |")
    lines.append(f"| 报告有效性 | {engagement.get('validity_note', '代码、配置或依赖变化后应重新扫描。')} |")
    lines.append(f"| 数据保留 | {engagement.get('retention_note', '公开报告前检查敏感信息。')} |")
    lines.append("")
    add_section("端点权限矩阵")
    lines.append("")
    authz = payload.get("authz") or {}
    endpoints = authz.get("endpoints") or []
    coverage = authz.get("coverage") or {}
    if endpoints:
        lines.append(
            f"共 {coverage.get('endpoints', 0)} 个端点：权限已证明 {coverage.get('proven', 0)} 个"
            f"（{coverage.get('confirmed_ratio', 0)}%），权限缺失 {coverage.get('missing', 0)} 个，"
            f"匿名可访问 {coverage.get('anonymous', 0)} 个，配置规则 {coverage.get('rules', 0)} 条。"
        )
        if coverage.get("unprotected_high_risk"):
            lines.append("")
            lines.append(f"> 注意：{coverage.get('unprotected_high_risk')} 个端点存在危险操作但身份要求为匿名或未知，建议优先人工确认。")
        lines.append("")
        lines.append("| 接口 | 方法 | 身份要求 | 角色 / 权限 | 危险操作 | 证据状态 |")
        lines.append("|---|---|---|---|---|---|")
        requirement_labels = {
            "anonymous": "无需登录", "authenticated": "需登录", "role": "需角色",
            "permission": "需权限", "ownership": "需数据归属", "unknown": "未知",
        }
        status_labels_authz = {"proven": "权限已证明", "inferred": "权限推测", "missing": "权限缺失"}
        for endpoint in endpoints:
            roles = endpoint.get("roles") or []
            permissions = endpoint.get("permissions") or []
            role_text = ", ".join(str(item) for item in roles + permissions) or "—"
            ops = endpoint.get("dangerous_ops") or []
            ops_text = ", ".join(str(item) for item in ops[:4]) or "—"
            requirement = requirement_labels.get(str(endpoint.get("requirement", "unknown")), str(endpoint.get("requirement", "unknown")))
            status = status_labels_authz.get(str(endpoint.get("status", "missing")), str(endpoint.get("status", "missing")))
            lines.append(
                f"| `{endpoint.get('route', '') or '/'}` | {endpoint.get('http_method', '')} | {requirement} | "
                f"{role_text} | {ops_text} | {status} |"
            )
    else:
        lines.append("未识别到 HTTP 端点：项目可能不是 Web 服务，或路由写法不在当前模型内（Spring MVC / JAX-RS）。")
    lines.append("")
    incremental = payload.get("incremental") or {}
    if incremental.get("enabled"):
        add_section("Git 增量审计")
        lines.append("")
        inc_stats = incremental.get("stats") or {}
        inc_mode = {"working": "工作区未提交变更", "ref": "与指定分支比较", "commit": "单次提交"}.get(
            str(incremental.get("mode", "")), str(incremental.get("mode", ""))
        )
        lines.append(f"- 模式：{inc_mode}；基准：`{incremental.get('base', '')}`")
        lines.append(
            f"- 变更文件 {inc_stats.get('files_changed', 0)} 个（Java {inc_stats.get('java_files_changed', 0)} 个），"
            f"依赖闭包 {inc_stats.get('closure_files', 0)} 个，变更行 {inc_stats.get('lines_changed', 0)} 行"
        )
        for focus in incremental.get("review_focus") or []:
            lines.append(f"- 焦点：{focus}")
        inc_authz = incremental.get("authz_changes") or []
        if inc_authz:
            lines.append("")
            lines.append("| 接口 | 方法 | 变化 | 原角色/权限 | 现角色/权限 | 说明 |")
            lines.append("|---|---|---|---|---|---|")
            change_labels = {"weakened": "放宽", "strengthened": "收紧", "added": "新增端点", "removed": "移除端点", "role_changed": "角色变化"}
            for item in inc_authz:
                old_roles = ", ".join(str(x) for x in (item.get("old_roles") or [])) or "—"
                new_roles = ", ".join(str(x) for x in (item.get("new_roles") or [])) or "—"
                lines.append(
                    f"| `{item.get('route', '')}` | {item.get('method', '')} | "
                    f"{change_labels.get(str(item.get('change', '')), str(item.get('change', '')))} | "
                    f"{old_roles} | {new_roles} | {item.get('detail', '')} |"
                )
        inc_new = incremental.get("new_findings") or []
        lines.append("")
        if inc_new:
            lines.append(f"本次变更引入 {len(inc_new)} 条发现：")
            lines.append("")
            lines.append("| 规则 | 严重度 | 位置 | 所属端点 | 备注 |")
            lines.append("|---|---|---|---|---|")
            variant_keys = {f"{item.get('rule_id')}{item.get('line')}" for item in (incremental.get("variant_findings") or [])}
            for item in inc_new:
                marker = "同类新位置" if f"{item.get('rule_id')}{item.get('line')}" in variant_keys else ""
                lines.append(
                    f"| `{item.get('rule_id', '')}` | {item.get('severity', '')} | "
                    f"`{item.get('path', '')}:{item.get('line', 0)}` | {item.get('endpoint') or '—'} | {marker} |"
                )
        else:
            lines.append("本次变更未引入新的发现。")
        inc_fixed = incremental.get("fixed_findings") or []
        if inc_fixed:
            lines.append("")
            lines.append("| 规则 | 原位置 | 修复状态 | 说明 |")
            lines.append("|---|---|---|---|")
            for item in inc_fixed:
                lines.append(
                    f"| `{item.get('rule_id', '')}` | `{item.get('path', '')}:{item.get('line', 0)}` | "
                    f"{item.get('status', '')} | {item.get('note', '')} |"
                )
        for note in incremental.get("notes") or []:
            lines.append(f"- 说明：{note}")
        lines.append("")
    add_section("发现详情（按复核优先级降序）")
    lines.append("")
    path_labels = {"proven": "已证明路径", "inferred": "推测路径", "missing": "缺失路径", "unresolved": "无法解析（动态调用）"}
    for number, finding in enumerate(findings, start=1):
        loc = finding["location"]
        assessment = finding.get("metadata", {}).get("path_assessment", {})
        conclusion = str(assessment.get("conclusion", "missing"))
        review = finding.get("review") or {}
        verdict = {"confirmed": "确认漏洞", "false-positive": "误报", "uncertain": "仍不确定"}.get(str(review.get("verdict")), "待复核")
        lines.append(f"### VULN-{number:03d} {finding['title']}（{finding['cwe']}）")
        lines.append("")
        lines.append(f"- 严重程度：{finding['severity']}　置信度：{finding['confidence']}　复核优先级：{finding.get('review_priority', 0)}/100")
        lines.append(f"- 复核状态：{verdict}")
        lines.append(f"- 位置：`{loc['path']}:{loc['line']}`")
        scope = str(finding.get("metadata", {}).get("scope", "production"))
        scope_name = {"production": "生产代码", "test": "测试代码", "generated": "生成代码", "example": "示例代码"}.get(scope, scope)
        lines.append(f"- 代码范围：{scope_name}")
        lines.append(f"- 扫描器：{', '.join(finding.get('metadata', {}).get('scanners', [finding['scanner']]))}")
        record = finding.get("metadata", {}).get("evidence_record") or {}
        if record:
            source_rec = record.get("source") or {}
            sink_rec = record.get("sink") or {}
            lines.append(f"- 统一证据：来源 `{source_rec.get('path') or '未采集'}:{source_rec.get('line', 0)}` → 传播 {len(record.get('propagation') or [])} 步 → 终点 `{sink_rec.get('path') or '未采集'}:{sink_rec.get('line', 0)}`")
            engines = record.get("engine_evidence") or []
            if engines:
                engine_text = "; ".join(f"{e.get('scanner', '')}({e.get('rule_id', '')})" for e in engines)
                lines.append(f"- 引擎佐证：{engine_text}")
            sanitizers = record.get("sanitizers") or []
            if sanitizers:
                lines.append(f"- 净化/抑制反证：{'; '.join(str(s.get('detail', s))[:160] for s in sanitizers)}")
        authorization = finding.get("metadata", {}).get("authorization") or {}
        if authorization:
            roles = authorization.get("roles") or []
            permissions = authorization.get("permissions") or []
            role_text = ", ".join(str(item) for item in roles + permissions) or "—"
            lines.append(
                f"- 端点权限：`{authorization.get('endpoint', '')}` · 身份要求 {authorization.get('requirement', '未知')}"
                f" · 角色/权限 {role_text} · {authorization.get('status', '')}"
            )
        lines.append(f"- 描述：{finding['description']}")
        lines.append("")
        lines.append("**证据代码**")
        lines.append("")
        lines.append("```java")
        lines.append(str(finding["evidence"])[:500])
        lines.append("```")
        lines.append("")
        lines.append(f"**Source → Sink 路径（{path_labels.get(conclusion, '缺失路径')}）**")
        lines.append("")
        trace = finding.get("trace", [])
        if trace:
            for step in trace:
                kind = str(step.get("kind", "步骤"))
                level = "已证明" if kind == "flow" else ("推测" if kind in {"source-candidate", "parameter-candidate", "propagation-candidate"} else "")
                lines.append(f"- `{step.get('path', '')}:{step.get('line', 1)}` {step.get('label', '')}{'（' + level + '）' if level else ''}")
        else:
            lines.append("- 无可用路径证据；入口到危险操作的调用链需要人工补齐，工具不会虚构中间步骤。")
        lines.append("")
        five_answers = (review.get("answers") or {}) if isinstance(review, dict) else {}
        lines.append("**漏洞成立五问**")
        lines.append("")
        for index, (key, text, _labels) in enumerate(FIVE_QUESTIONS, start=1):
            answer = five_answers.get(key, "未回答")
            lines.append(f"{index}. {text}")
            lines.append(f"   - 回答：{answer}")
        lines.append("")
        lines.append("**成立条件与反证**")
        lines.append("")
        lines.append("- 支持漏洞假设：")
        for item in finding["evidence_for"]:
            lines.append(f"  - [ ] {item}")
        lines.append("- 能够推翻假设：")
        for item in finding["evidence_against"]:
            lines.append(f"  - [ ] {item}")
        lines.append("")
        lines.append(f"**攻击后果（保守估计）**：{finding['description']}")
        lines.append("")
        lines.append(f"**修复建议**：{finding['remediation']}")
        generalization = finding.get("metadata", {}).get("generalization") or {}
        if generalization.get("same_rule") or generalization.get("same_cwe_other_rule_count"):
            lines.append("")
            lines.append("**同类位置**（确认本条后优先复核）：")
            for item in generalization.get("same_rule", [])[:20]:
                lines.append(f"  - `{item.get('path')}:{item.get('line')}`")
            if generalization.get("same_cwe_other_rule_count"):
                lines.append(f"  - 另有 {generalization['same_cwe_other_rule_count']} 条同 CWE 不同规则的线索，见报告列表")
        lines.append("")
    add_section("全局加固建议")
    lines.append("")
    cwes = sorted({str(finding["cwe"]) for finding in findings if str(finding["cwe"]).startswith("CWE-")})
    if "CWE-89" in cwes:
        lines.append("- 统一数据访问层：所有动态值一律参数化，动态表名/排序字段走固定白名单。")
    if "CWE-78" in cwes:
        lines.append("- 移除系统命令执行；确需执行时集中到独立模块，程序与参数固定并审计日志。")
    if "CWE-798" in cwes:
        lines.append("- 建立秘密管理：凭据从环境或秘密服务注入，仓库接入泄漏扫描。")
    if "CWE-502" in cwes:
        lines.append("- 反序列化统一入口：签名与类型白名单（ObjectInputFilter），优先安全格式。")
    if not cwes:
        lines.append("- 本轮未发现可归纳的系统性问题；保持扫描器与基线复查节奏即可。")
    lines.append("")
    add_section("待人工确认项")
    lines.append("")
    pending = [f for f in findings if not (f.get("review") or {}).get("verdict")]
    if not pending:
        lines.append("- 所有线索均已给出人工结论。")
    else:
        for number, finding in enumerate(pending, start=1):
            loc = finding["location"]
            lines.append(f"{number}. `{loc['path']}:{loc['line']}` {finding['title']}（{finding['cwe']}）——需补齐五问证据后给出结论。")
        lines.append("")
        lines.append("另见审计阶段『部分完成』项的缺口清单；反射/动态调用与缺失路径需要运行时或日志佐证。")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("*本报告由规则引擎与数据流证据驱动生成；AI 仅提供学习解释，不能把线索升级为确认漏洞。修复后请以本报告为基线复测。*")
    return chr(10).join(lines)
