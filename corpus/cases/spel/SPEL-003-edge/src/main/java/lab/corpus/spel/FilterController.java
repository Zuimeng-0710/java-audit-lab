package lab.corpus.spel;

import java.util.List;
import java.util.Map;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class FilterController {

    @PostMapping("/users/search")
    public List<String> search(@RequestBody Map<String, String> payload) {
        String filter = payload.get("filter");
        if (!filter.startsWith("username") && !filter.startsWith("dept")) {
            throw new IllegalArgumentException("filter must start with username or dept");
        }
        ExpressionParser parser = new SpelExpressionParser();
        Boolean matched = parser.parseExpression(filter)
                .getValue(new StandardEvaluationContext(user), Boolean.class);
        return userService.pick(matched);
    }
}
