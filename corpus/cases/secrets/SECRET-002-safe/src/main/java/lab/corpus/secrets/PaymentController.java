package lab.corpus.secrets;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 语料样本（安全）：密钥由部署配置注入，源码与仓库中不出现字面值。
 */
@RestController
public class PaymentController {

    private final String paymentApiKey;

    private final HttpClient client = HttpClient.newHttpClient();

    public PaymentController(@Value("${payment.api-key}") String paymentApiKey) {
        this.paymentApiKey = paymentApiKey;
    }

    @PostMapping("/api/payment/charge")
    public String charge(@RequestParam("orderId") String orderId) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://api.payment.example.com/v1/charge"))
                .header("Authorization", "Bearer " + paymentApiKey)
                .POST(HttpRequest.BodyPublishers.ofString("orderId=" + orderId))
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        return response.body();
    }
}
