package lab.corpus.deser;

import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class NoteSyncController {

    @PostMapping("/sync/note3")
    public String syncNoteFiltered(HttpServletRequest request) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(request.getInputStream())) {
            ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter(
                    "lab.corpus.deser.NotePayload;java.base.*;!*"));
            Object obj = ois.readObject();
            return ((NotePayload) obj).getContent();
        }
    }
}
