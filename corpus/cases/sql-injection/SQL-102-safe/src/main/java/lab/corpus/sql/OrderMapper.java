package lab.corpus.sql;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class OrderMapper {

    private final Connection connection;

    public OrderMapper(Connection connection) {
        this.connection = connection;
    }

    public String queryByName(String keyword) throws SQLException {
        PreparedStatement ps = connection.prepareStatement("SELECT * FROM orders WHERE name = ?");
        ps.setString(1, keyword);
        ResultSet rs = ps.executeQuery();
        return rs.next() ? rs.getString(1) : "not found";
    }
}
