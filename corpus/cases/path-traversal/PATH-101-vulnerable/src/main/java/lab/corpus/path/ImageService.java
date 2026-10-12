package lab.corpus.path;

import org.springframework.stereotype.Service;

import java.io.File;
import java.nio.file.Files;
import java.util.Base64;

@Service
public class ImageService {

    public String readImage(String imgPath) throws Exception {
        File image = new File("/srv/gallery/" + imgPath);
        if (!image.exists() || image.isDirectory()) {
            return "image not found";
        }
        byte[] data = Files.readAllBytes(image.toPath());
        return Base64.getEncoder().encodeToString(data);
    }
}
