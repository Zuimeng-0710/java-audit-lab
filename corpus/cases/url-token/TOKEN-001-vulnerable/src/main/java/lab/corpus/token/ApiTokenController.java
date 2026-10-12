package lab.corpus.token;

import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ApiTokenController {

    @GetMapping("/api/data")
    public String data(HttpServletRequest request) {
        String token = request.getParameter("token");
        if (tokenService.verify(token)) {
            return dataService.fetch();
        }
        throw new SecurityException("invalid token");
    }
}
