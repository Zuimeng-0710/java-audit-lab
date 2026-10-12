package lab.corpus.xxe;

import java.io.InputStream;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MenuResourceController {

    @GetMapping("/app/menu")
    public String menu() throws Exception {
        try (InputStream in = getClass().getResourceAsStream("/app-menu.xml")) {
            SAXParserFactory factory = SAXParserFactory.newInstance();
            SAXParser parser = factory.newSAXParser();
            MenuHandler handler = new MenuHandler();
            parser.parse(in, handler);
            return handler.toJson();
        }
    }
}
