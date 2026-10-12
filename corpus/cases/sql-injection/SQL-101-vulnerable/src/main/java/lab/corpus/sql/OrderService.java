package lab.corpus.sql;

import org.springframework.stereotype.Service;

@Service
public class OrderService {

    private final OrderMapper orderMapper;

    public OrderService(OrderMapper orderMapper) {
        this.orderMapper = orderMapper;
    }

    public String findByName(String keyword) {
        return orderMapper.queryByName(keyword);
    }
}
