package lab.corpus.redirect;

import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LogoutController {

    @GetMapping("/logout")
    public void logout(@RequestParam String redirect, HttpServletResponse response) throws Exception {
        sessionService.clear();
        response.sendRedirect(redirect);
    }
}
