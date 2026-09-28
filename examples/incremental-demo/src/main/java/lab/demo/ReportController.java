package lab.demo;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.PreparedStatement;

@RestController
@RequestMapping("/report")
public class ReportController {

    // 本次变更删除了 @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/export")
    public String export(@RequestParam String file) throws Exception {
        return new String(Files.readAllBytes(Paths.get(file)));
    }

    // v3 修复：改为预编译参数化查询
    @GetMapping("/search")
    public String search(@RequestParam String keyword) throws Exception {
        PreparedStatement stmt = null;
        stmt.setString(1, keyword);
        return stmt.executeQuery().toString();
    }
}
