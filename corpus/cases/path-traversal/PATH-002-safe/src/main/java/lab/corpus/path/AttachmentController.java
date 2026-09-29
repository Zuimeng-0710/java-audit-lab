package lab.corpus.path;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.springframework.core.io.FileSystemResource;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 语料样本（安全）：只接受服务端生成的存储标识，规范化后做目录边界校验。
 */
@RestController
public class AttachmentController {

    private final Path storageRoot = Path.of("/srv/app/storage");

    @GetMapping("/api/attachments/download")
    public ResponseEntity<FileSystemResource> download(@RequestParam("id") String storedId) throws IOException {
        Path resolved = storageRoot.resolve(storedId).normalize();
        if (!resolved.startsWith(storageRoot)) {
            return ResponseEntity.badRequest().build();
        }
        if (!Files.isRegularFile(resolved)) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(new FileSystemResource(resolved.toFile()));
    }
}
