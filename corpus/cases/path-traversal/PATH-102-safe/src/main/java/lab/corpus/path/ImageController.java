package lab.corpus.path;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ImageController {

    private final ImageService imageService;

    public ImageController(ImageService imageService) {
        this.imageService = imageService;
    }

    @GetMapping("/image/view")
    public String view(@RequestParam String imgRef) throws Exception {
        return imageService.readImage(imgRef);
    }
}
