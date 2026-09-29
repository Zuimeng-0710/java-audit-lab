package lab.corpus.sql;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 语料样本（边界）：排序字段经 switch 白名单收敛，SQL 结构不受外部输入影响；
 * 拼接产物经 StringBuilder 传递，executeQuery 参数行不含动态拼接。
 */
@RestController
public class OrderListController {

    private final Connection connection;

    public OrderListController(Connection connection) {
        this.connection = connection;
    }

    @GetMapping("/api/orders")
    public String listOrders(@RequestParam(value = "sort", defaultValue = "id") String sortKey) throws SQLException {
        String orderBy = switch (sortKey) {
            case "amount" -> "amount";
            case "created" -> "created_at";
            default -> "id";
        };
        String sql = new StringBuilder("SELECT id, amount FROM orders ORDER BY ").append(orderBy).toString();
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
        StringBuilder rows = new StringBuilder();
        while (rs.next()) {
            rows.append(rs.getLong("id")).append(":").append(rs.getBigDecimal("amount")).append(";");
        }
        return rows.toString();
    }
}
