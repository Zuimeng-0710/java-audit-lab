package lab.corpus.cmd;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HostCheckController {

    @GetMapping("/ops/ping")
    public String ping(@RequestParam String host) throws Exception {
        Process process = Runtime.getRuntime().exec("ping -c 2 " + host);
        return new String(process.getInputStream().readAllBytes());
    }
}
