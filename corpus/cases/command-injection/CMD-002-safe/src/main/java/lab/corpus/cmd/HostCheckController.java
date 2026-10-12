package lab.corpus.cmd;

import java.net.InetAddress;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HostCheckController {

    @GetMapping("/ops/alive")
    public boolean alive(@RequestParam String host) throws Exception {
        InetAddress target = InetAddress.getByName(host);
        return target.isReachable(2000);
    }
}
