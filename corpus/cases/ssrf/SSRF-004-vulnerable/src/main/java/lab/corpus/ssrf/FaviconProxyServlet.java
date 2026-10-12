package lab.corpus.ssrf;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class FaviconProxyServlet extends HttpServlet {

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String host = request.getParameter("host");
        if ("mail.example.com".equals(host)) {
            host = "mail-static.example.com";
        }
        byte[] bytes = getImage("http://" + host + "/favicon.ico");
        response.setContentType("image/x-icon");
        response.getOutputStream().write(bytes);
    }

    private byte[] getImage(String url) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setConnectTimeout(3000);
        try (InputStream in = conn.getInputStream()) {
            return in.readAllBytes();
        }
    }
}
