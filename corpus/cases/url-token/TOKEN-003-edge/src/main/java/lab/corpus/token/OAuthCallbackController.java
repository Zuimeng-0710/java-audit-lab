package lab.corpus.token;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OAuthCallbackController {

    @GetMapping("/oauth/callback")
    public String callback(HttpServletRequest request) {
        String code = request.getParameter("code");
        String state = request.getParameter("state");
        HttpSession session = request.getSession();
        if (!stateService.check(session, state)) {
            throw new SecurityException("state mismatch");
        }
        return oauthService.exchange(code);
    }
}
