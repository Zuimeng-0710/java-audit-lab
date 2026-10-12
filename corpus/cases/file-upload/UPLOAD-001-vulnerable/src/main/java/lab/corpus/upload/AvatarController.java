package lab.corpus.upload;

import java.nio.file.Path;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
public class AvatarController {

    @PostMapping("/avatar")
    public String upload(@RequestPart MultipartFile file) throws Exception {
        String original = file.getOriginalFilename();
        Path target = Path.of(uploadDir, original);
        file.transferTo(target);
        return target.toString();
    }
}
