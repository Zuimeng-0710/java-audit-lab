package lab.corpus.cmd;

import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;

@Service
public class DiagService {

    private static final Map<String, String> ALLOWED_CHECKS = new HashMap<>();

    static {
        ALLOWED_CHECKS.put("disk", "/usr/bin/df -h");
        ALLOWED_CHECKS.put("memory", "/usr/bin/free -m");
    }

    public String runCheck(String action) {
        String resolved = ALLOWED_CHECKS.get(action);
        if (resolved == null) {
            return "unknown check";
        }
        try {
            Process p = Runtime.getRuntime().exec(resolved);
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            StringBuilder out = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                out.append(line);
            }
            return out.toString();
        } catch (Exception e) {
            return "diag failed";
        }
    }
}
