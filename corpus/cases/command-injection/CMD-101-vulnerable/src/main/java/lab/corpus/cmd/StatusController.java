package lab.corpus.cmd;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class StatusController {

    private final DiagService diagService;

    public StatusController(DiagService diagService) {
        this.diagService = diagService;
    }

    @GetMapping("/diag/ping")
    public String ping(@RequestParam String host) {
        return diagService.runPing(host);
    }
}
