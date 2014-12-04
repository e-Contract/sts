package test.integ.be.e_contract.sts;

import org.apache.cxf.sts.request.ReceivedToken;
import org.apache.cxf.sts.request.ReceivedToken.STATE;
import org.apache.cxf.sts.token.delegation.TokenDelegationHandler;
import org.apache.cxf.sts.token.delegation.TokenDelegationParameters;
import org.apache.cxf.sts.token.delegation.TokenDelegationResponse;
import org.apache.ws.security.CustomTokenPrincipal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ExampleTokenDelegationHandler implements TokenDelegationHandler {

	private static final Logger LOGGER = LoggerFactory
			.getLogger(ExampleTokenDelegationHandler.class);

	@Override
	public boolean canHandleToken(ReceivedToken paramReceivedToken) {
		LOGGER.debug("canHandleToken");
		return paramReceivedToken.isDOMElement();
	}

	@Override
	public TokenDelegationResponse isDelegationAllowed(
			TokenDelegationParameters paramTokenDelegationParameters) {
		LOGGER.debug("isDelegationAllowed");
		TokenDelegationResponse response = new TokenDelegationResponse();
		LOGGER.debug("param principal: "
				+ paramTokenDelegationParameters.getPrincipal().getName());
		response.setDelegationAllowed(true);
		ReceivedToken receivedToken = paramTokenDelegationParameters.getToken();
		receivedToken.setState(STATE.VALID);
		CustomTokenPrincipal customTokenPrincipal = new CustomTokenPrincipal(
				paramTokenDelegationParameters.getPrincipal().getName());
		customTokenPrincipal.setTokenObject(receivedToken);
		receivedToken.setPrincipal(customTokenPrincipal);
		response.setToken(receivedToken);
		return response;
	}
}
