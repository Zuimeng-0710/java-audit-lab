package lab.corpus.crypto;

import java.io.InputStream;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import org.springframework.stereotype.Service;

@Service
public class ChecksumService {

    public String checksum(Path file) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        try (InputStream in = java.nio.file.Files.newInputStream(file)) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) {
                md.update(buf, 0, n);
            }
        }
        return HexFormat.of().formatHex(md.digest());
    }
}
