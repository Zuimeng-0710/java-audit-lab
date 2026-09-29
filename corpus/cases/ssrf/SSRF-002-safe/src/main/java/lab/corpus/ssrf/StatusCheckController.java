package lab.corpus.ssrf;

import java.io.InputStream;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 语料样本（安全）：出站主机固定为字面量常量，用户输入只进入已编码的查询参数，
 * 不存在目标可控。
 */
@RestController
public class StatusCheckController {

    @PostMapping("/api/status/check")
    public String checkStatus(@RequestParam("nonce") String nonce) throws Exception {
        String encoded = URLEncoder.encode(nonce, StandardCharsets.UTF_8);
        URL target = new URL("https://status.internal.example.com/api/v1/ping?nonce=" + encoded);
        try (InputStream body = target.openStream()) {
            return body.readAllBytes().length + " bytes received";
        }
    }
}
