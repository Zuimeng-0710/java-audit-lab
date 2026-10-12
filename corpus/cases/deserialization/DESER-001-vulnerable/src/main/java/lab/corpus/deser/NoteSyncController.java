package lab.corpus.deser;

import java.io.ObjectInputStream;
import java.io.Serializable;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class NoteSyncController {

    @PostMapping("/sync/note")
    public String syncNote(HttpServletRequest request) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(request.getInputStream())) {
            Object obj = ois.readObject();
            if (obj instanceof NotePayload) {
                return ((NotePayload) obj).getContent();
            }
            return "ignored";
        }
    }
}
