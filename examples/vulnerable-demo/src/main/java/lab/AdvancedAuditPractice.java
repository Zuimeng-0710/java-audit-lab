package lab;

import java.io.ObjectInputStream;
import java.net.URL;
import java.security.MessageDigest;

public class AdvancedAuditPractice {
    interface ExpressionParser { Object parseExpression(String value); }

    public Object deserialize(ObjectInputStream input) throws Exception {
        return input.readObject();
    }

    public void request(String url) throws Exception {
        new URL(url).openConnection();
    }

    public Object expression(ExpressionParser parser, String expression) {
        return parser.parseExpression(expression);
    }

    public byte[] legacyHash(byte[] content) throws Exception {
        return MessageDigest.getInstance("MD5").digest(content);
    }
}
