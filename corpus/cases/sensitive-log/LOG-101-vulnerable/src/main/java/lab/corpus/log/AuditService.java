package lab.corpus.log;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class AuditService {

    private static final Logger logger = LoggerFactory.getLogger(AuditService.class);

    public void recordLogin(String accountId, String token) {
        logger.info("login token=" + token + " for account " + accountId);
    }
}
