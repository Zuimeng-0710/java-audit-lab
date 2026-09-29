package lab.corpus.path;

import java.io.File;
import java.io.IOException;

import org.apache.commons.io.FilenameUtils;
import org.springframework.core.io.FileSystemResource;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 语料样本（边界）：请求参数先经 FilenameUtils.getName 剥离路径分量，
 * 再拼接到服务端缓存目录，目录穿越不可达。
 */
@RestController
public class ReportPreviewController {

    private final File cacheDir = new File("/srv/app/cache");

    @GetMapping("/api/reports/preview")
    public ResponseEntity<FileSystemResource> preview(@RequestParam("report") String reportRef) throws IOException {
        String base = FilenameUtils.getName(reportRef);
        if (base == null || base.isBlank()) {
            return ResponseEntity.badRequest().build();
        }
        File preview = new File(cacheDir, base);
        FileSystemResource resource = new FileSystemResource(preview);
        if (!resource.exists()) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(resource);
    }
}
