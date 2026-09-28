package lab;

import java.nio.file.Path;
import java.sql.Connection;

public class SaferPractice {
    public void query(Connection connection, String userInput) throws Exception {
        var statement = connection.prepareStatement("SELECT * FROM users WHERE name = ?");
        statement.setString(1, userInput);
        statement.executeQuery();
    }

    public Path download(Path allowedRoot, String serverGeneratedName) {
        Path result = allowedRoot.resolve(serverGeneratedName).normalize();
        if (!result.startsWith(allowedRoot.normalize())) throw new IllegalArgumentException("invalid path");
        return result;
    }
}
