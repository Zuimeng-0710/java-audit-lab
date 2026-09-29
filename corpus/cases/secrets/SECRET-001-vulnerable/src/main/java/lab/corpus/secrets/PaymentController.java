package lab.corpus.secrets;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 语料样本（危险）：支付网关密钥硬编码在源码中。
 * 值为语料专用占位符 CORPUS_FAKE_KEY_DO_NOT_USE_001，非真实凭据。
 */
@RestController
public class PaymentController {

    private static final String API_KEY = "CORPUS_FAKE_KEY_DO_NOT_USE_001";

    private final HttpClient client = HttpClient.newHttpClient();

    @PostMapping("/api/payment/charge")
    public String charge(@RequestParam("orderId") String orderId) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://api.payment.example.com/v1/charge"))
                .header("Authorization", "Bearer " + API_KEY)
                .POST(HttpRequest.BodyPublishers.ofString("orderId=" + orderId))
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        return response.body();
    }
}
