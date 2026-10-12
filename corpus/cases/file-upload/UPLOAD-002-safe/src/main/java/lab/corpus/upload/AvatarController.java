package lab.corpus.upload;

import java.nio.file.Path;
import java.util.UUID;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
public class AvatarController {

    @PostMapping("/avatar2")
    public String upload(@RequestPart MultipartFile file) throws Exception {
        String storedName = UUID.randomUUID() + ".png";
        Path target = Path.of(uploadDir, storedName);
        file.transferTo(target);
        return storedName;
    }
}
