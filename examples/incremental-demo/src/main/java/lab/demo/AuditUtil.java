package lab.demo;

public class AuditUtil {
    public static String safe(String in) {
        return in.replace("<", "");
    }
}
