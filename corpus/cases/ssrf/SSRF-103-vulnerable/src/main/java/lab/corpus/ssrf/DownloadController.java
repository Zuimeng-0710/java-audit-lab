package lab.corpus.ssrf;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.InputStream;

@RestController
public class DownloadController {

    @GetMapping("/download/avatar")
    public byte[] download(@RequestParam String url) throws Exception {
        java.net.URL u = new java.net.URL(url);
        InputStream in = u.openStream();
        try {
            return readAll(in);
        } finally {
            in.close();
        }
    }

    private byte[] readAll(InputStream in) throws Exception {
        java.io.ByteArrayOutputStream buffer = new java.io.ByteArrayOutputStream();
        byte[] chunk = new byte[4096];
        int n;
        while ((n = in.read(chunk)) > 0) {
            buffer.write(chunk, 0, n);
        }
        return buffer.toByteArray();
    }
}
