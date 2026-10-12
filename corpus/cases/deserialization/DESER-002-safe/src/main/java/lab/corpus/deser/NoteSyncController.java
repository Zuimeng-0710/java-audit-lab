package lab.corpus.deser;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class NoteSyncController {

    @PostMapping("/sync/note2")
    public String syncNoteJson(@RequestBody NotePayload payload) {
        return payload.getContent();
    }
}
