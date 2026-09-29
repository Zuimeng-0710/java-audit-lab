package lab.corpus.path;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;

import org.springframework.core.io.FileSystemResource;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 语料样本（危险）：文件名来自请求参数并直接参与服务端文件路径构造。
 * 来源：synthetic，不含真实业务信息。
 */
@RestController
public class AttachmentController {

    private final Path storageRoot = Path.of("/srv/app/storage");

    @GetMapping("/api/attachments/download")
    public ResponseEntity<FileSystemResource> download(@RequestParam("file") String fileName) throws IOException {
        File target = new File(storageRoot.toString(), fileName);
        FileSystemResource resource = new FileSystemResource(target);
        if (!resource.exists()) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(resource);
    }
}
