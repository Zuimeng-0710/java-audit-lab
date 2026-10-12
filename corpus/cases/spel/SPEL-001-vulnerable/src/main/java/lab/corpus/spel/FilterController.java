package lab.corpus.spel;

import java.util.List;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class FilterController {

    @PostMapping("/users/filter")
    public List<String> filter(@RequestParam String expr) {
        ExpressionParser parser = new SpelExpressionParser();
        StandardEvaluationContext context = new StandardEvaluationContext();
        Expression expression = parser.parseExpression(expr);
        Object value = expression.getValue(context);
        return userService.match(value);
    }
}
