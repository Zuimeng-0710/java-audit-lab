package lab.corpus.ssrf;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class WebhookController {

    private final HttpHelper httpHelper;

    public WebhookController(HttpHelper httpHelper) {
        this.httpHelper = httpHelper;
    }

    @GetMapping("/webhook/fetch")
    public String fetch(@RequestParam String url) {
        return httpHelper.get(url);
    }
}
