package lab.corpus.sql;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 语料样本（安全）：PreparedStatement 占位符参数绑定，外部输入不进入 SQL 文本。
 */
@RestController
public class OrderQueryController {

    private final Connection connection;

    public OrderQueryController(Connection connection) {
        this.connection = connection;
    }

    @GetMapping("/api/orders/search")
    public String searchOrders(@RequestParam("keyword") String userInput) throws SQLException {
        PreparedStatement stmt = connection.prepareStatement("SELECT id, amount FROM orders WHERE remark = ?");
        stmt.setString(1, userInput);
        ResultSet rs = stmt.executeQuery();
        StringBuilder rows = new StringBuilder();
        while (rs.next()) {
            rows.append(rs.getLong("id")).append(":").append(rs.getBigDecimal("amount")).append(";");
        }
        return rows.toString();
    }
}
