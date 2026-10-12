package lab.corpus.token;

import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ApiTokenController {

    @GetMapping("/api/data2")
    public String data(HttpServletRequest request) {
        String auth = request.getHeader("Authorization");
        if (tokenService.verifyBearer(auth)) {
            return dataService.fetch();
        }
        throw new SecurityException("invalid token");
    }
}
