package lab.corpus.path;

import org.springframework.stereotype.Service;

import java.io.File;
import java.nio.file.Files;
import java.util.Base64;

@Service
public class ImageService {

    private static final String GALLERY_ROOT = "/srv/gallery";

    public String readImage(String imgRef) throws Exception {
        File candidate = new File(GALLERY_ROOT, imgRef).getCanonicalFile();
        File root = new File(GALLERY_ROOT).getCanonicalFile();
        if (!candidate.toPath().startsWith(root.toPath())) {
            throw new SecurityException("path escapes gallery root");
        }
        if (!candidate.exists() || candidate.isDirectory()) {
            return "image not found";
        }
        byte[] data = Files.readAllBytes(candidate.toPath());
        return Base64.getEncoder().encodeToString(data);
    }
}
