package lab.corpus.cmd;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HostCheckController {

    @GetMapping("/ops/trace")
    public String trace(@RequestParam String host) throws Exception {
        Process process = Runtime.getRuntime().exec(new String[]{"traceroute", host});
        return new String(process.getInputStream().readAllBytes());
    }
}
