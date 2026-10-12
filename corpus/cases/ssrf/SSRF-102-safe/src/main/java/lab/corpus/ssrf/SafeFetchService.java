package lab.corpus.ssrf;

import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

@Service
public class SafeFetchService {

    private static final Set<String> ALLOWED_HOSTS = new HashSet<>(
            Arrays.asList("status.example.com", "health.example.org"));

    public String fetchStatus(String target) {
        if (!ALLOWED_HOSTS.contains(target)) {
            return "host not allowed";
        }
        java.net.URI uri = UriComponentsBuilder
                .fromHttpUrl("https://" + target)
                .path("/api/v1/ping")
                .build()
                .toUri();
        return "status ok";
    }
}
