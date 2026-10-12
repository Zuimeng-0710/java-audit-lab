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

    @GetMapping("/diag/check")
    public String check(@RequestParam String action) {
        return diagService.runCheck(action);
    }
}
