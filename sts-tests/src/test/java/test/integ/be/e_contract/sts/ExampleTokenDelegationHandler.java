/*
 * eID Security Token Service Project.
 * Copyright (C) 2014 e-Contract.be BVBA.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version
 * 3.0 as published by the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, see 
 * http://www.gnu.org/licenses/.
 */

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
				"custom-"
						+ paramTokenDelegationParameters.getPrincipal()
								.getName());
		customTokenPrincipal.setTokenObject(receivedToken);
		receivedToken.setPrincipal(customTokenPrincipal);
		response.setToken(receivedToken);
		return response;
	}
}
