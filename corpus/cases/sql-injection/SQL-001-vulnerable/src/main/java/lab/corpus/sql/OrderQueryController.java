package lab.corpus.sql;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 语料样本（危险）：请求参数直接拼接到 SQL 查询文本。
 * 来源：synthetic，不含真实业务信息。
 */
@RestController
public class OrderQueryController {

    private final Connection connection;

    public OrderQueryController(Connection connection) {
        this.connection = connection;
    }

    @GetMapping("/api/orders/search")
    public String searchOrders(@RequestParam("keyword") String userInput) throws SQLException {
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT id, amount FROM orders WHERE remark = '" + userInput + "'");
        StringBuilder rows = new StringBuilder();
        while (rs.next()) {
            rows.append(rs.getLong("id")).append(":").append(rs.getBigDecimal("amount")).append(";");
        }
        return rows.toString();
    }
}
