package lab.corpus.ssrf;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

public class HttpHelper {

    public String get(String url) {
        try {
            URL target = new URL(url);
            HttpURLConnection conn = (HttpURLConnection) target.openConnection();
            conn.setRequestMethod("GET");
            BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            StringBuilder out = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                out.append(line);
            }
            return out.toString();
        } catch (Exception e) {
            return "request failed";
        }
    }
}
