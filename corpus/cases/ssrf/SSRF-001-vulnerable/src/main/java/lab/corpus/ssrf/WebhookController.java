package lab.corpus.ssrf;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 语料样本（危险）：用户提供的 URL 直接作为服务端出站请求目标。
 * 来源：synthetic，不含真实业务信息。
 */
@RestController
public class WebhookController {

    @PostMapping("/api/webhook/test")
    public String testWebhook(@RequestParam("url") String userUrl) throws Exception {
        URL target = new URL(userUrl);
        HttpURLConnection conn = (HttpURLConnection) target.openConnection();
        conn.setConnectTimeout(3000);
        conn.setRequestMethod("GET");
        StringBuilder body = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                body.append(line);
            }
        }
        return body.toString();
    }
}
