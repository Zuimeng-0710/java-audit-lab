package lab;

import java.io.File;
import java.sql.Connection;
import javax.xml.parsers.DocumentBuilderFactory;

public class AuditPractice {
    private static final String API_KEY = "demo-secret-123456";

    public void query(Connection connection, String userInput) throws Exception {
        connection.createStatement().executeQuery("SELECT * FROM users WHERE name='" + userInput + "'");
    }

    public void run(String command) throws Exception {
        Runtime.getRuntime().exec(command);
    }

    public File download(String fileName) {
        return new File("uploads/" + fileName);
    }

    public void parse() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    }
}
