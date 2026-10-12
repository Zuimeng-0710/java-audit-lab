package lab.corpus.sql;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class OrderMapper {

    private final Connection connection;

    public OrderMapper(Connection connection) {
        this.connection = connection;
    }

    public String queryByName(String keyword) throws SQLException {
        Statement st = connection.createStatement();
        ResultSet rs = st.executeQuery("SELECT * FROM orders WHERE name = '" + keyword + "'");
        return rs.next() ? rs.getString(1) : "not found";
    }
}
