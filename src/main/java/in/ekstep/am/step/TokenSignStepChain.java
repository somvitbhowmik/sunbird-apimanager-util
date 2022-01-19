package in.ekstep.am.step;

import in.ekstep.am.dto.token.TokenSignRequest;
import in.ekstep.am.jwt.KeyManager;
import in.ekstep.am.builder.TokenSignResponseBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import java.util.List;
import static java.util.Arrays.asList;

@Component
public class TokenSignStepChain {

    private final Logger log = LoggerFactory.getLogger(this.getClass());
    @Autowired
    private KeyManager keyManager;

    public void execute(TokenSignRequest token, TokenSignResponseBuilder tokenSignResponseBuilder) throws Exception {
        log.info("INSIDE EXECUTE METHOD: ");
        for (TokenStep step : stepChain(token, tokenSignResponseBuilder)) {
            if (tokenSignResponseBuilder.successful()) {
                step.execute();
            }
        }
        log.info("SUCCESS FOR EXECUTE METHOD");
    }

    private List<TokenStep> stepChain(TokenSignRequest token, TokenSignResponseBuilder tokenSignResponseBuilder) {
        log.info("INSIDE stepChain METHOD ");
        TokenSignStep tokenSignStep = new TokenSignStep(token, tokenSignResponseBuilder, keyManager);
        return asList(tokenSignStep);
    }
}