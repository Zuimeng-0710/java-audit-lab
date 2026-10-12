package lab.corpus.ssrf;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class StatusController {

    private final SafeFetchService fetchService;

    public StatusController(SafeFetchService fetchService) {
        this.fetchService = fetchService;
    }

    @GetMapping("/status/fetch")
    public String fetch(@RequestParam String target) {
        return fetchService.fetchStatus(target);
    }
}
