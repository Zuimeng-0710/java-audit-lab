package lab.corpus.ssrf;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class FeedController {

    private final HttpHelper httpHelper;

    public FeedController(HttpHelper httpHelper) {
        this.httpHelper = httpHelper;
    }

    @GetMapping("/feed/pull")
    public String pull(@RequestParam String url) {
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            return "blocked: only http/https allowed";
        }
        return httpHelper.get(url);
    }
}
