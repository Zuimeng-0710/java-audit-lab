package lab.corpus.redirect;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ThemeController {

    @PostMapping("/theme/preview")
    public String preview(@RequestParam String returnUrl) {
        if (!returnUrl.startsWith("/")) {
            return "error";
        }
        themeService.apply("preview");
        return "redirect:" + returnUrl;
    }
}
