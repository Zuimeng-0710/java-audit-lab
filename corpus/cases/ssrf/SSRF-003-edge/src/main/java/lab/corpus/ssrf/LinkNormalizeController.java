package lab.corpus.ssrf;

import java.net.URI;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 语料样本（边界）：URI 对象仅用于提取路径部分并做字符白名单收敛，
 * 全程不发起任何网络请求。
 */
@RestController
public class LinkNormalizeController {

    @GetMapping("/api/link/normalize")
    public String normalizeLink(@RequestParam("url") String userUrl) {
        URI parsed = URI.create(userUrl);
        String pathOnly = parsed.getPath();
        return pathOnly.replaceAll("[^a-zA-Z0-9/_-]", "");
    }
}
