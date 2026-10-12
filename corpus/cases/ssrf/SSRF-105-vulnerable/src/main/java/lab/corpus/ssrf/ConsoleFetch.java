package lab.corpus.ssrf;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

public class ConsoleFetch {

    public static void main(String[] args) throws Exception {
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        System.out.print("Enter URL: ");
        String url = reader.readLine();

        URL target = new URL(url);
        HttpURLConnection conn = (HttpURLConnection) target.openConnection();
        conn.setRequestMethod("GET");
        BufferedReader resp = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        String line;
        while ((line = resp.readLine()) != null) {
            System.out.println(line);
        }
        resp.close();
    }
}
