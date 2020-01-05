/*
 * eID Security Token Service Project.
 * Copyright (C) 2020 e-Contract.be BVBA.
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

package test.integ.be.e_contract.sts.onbehalfof;

import org.apache.cxf.sts.request.ReceivedToken;
import org.apache.cxf.sts.token.delegation.SAMLDelegationHandler;
import org.apache.cxf.sts.token.delegation.TokenDelegationParameters;
import org.apache.cxf.sts.token.delegation.TokenDelegationResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

public class OnBehalfOfSAMLDelegationHandler extends SAMLDelegationHandler {

	private static final Logger LOGGER = LoggerFactory.getLogger(OnBehalfOfSAMLDelegationHandler.class);

	@Override
	public boolean canHandleToken(ReceivedToken delegateTarget) {
		return super.canHandleToken(delegateTarget);
	}

	private boolean isActAsToken(ReceivedToken receivedToken) {
		Object token = receivedToken.getToken();
		LOGGER.debug("token type: {}", token.getClass().getName());
		Element tokenElement = (Element) token;
		Node parentNode = tokenElement.getParentNode();
		LOGGER.debug("token parent: {}", parentNode.getNodeName());
		String localName = parentNode.getLocalName();
		String namespace = parentNode.getNamespaceURI();
		LOGGER.debug("namespace: {}", namespace);
		if (!"ActAs".equals(localName)) {
			return false;
		}
		if (!"http://docs.oasis-open.org/ws-sx/ws-trust/200802".equals(namespace)) {
			return false;
		}
		return true;
	}

	@Override
	public TokenDelegationResponse isDelegationAllowed(TokenDelegationParameters tokenParameters) {
		ReceivedToken receivedToken = tokenParameters.getToken();
		if (isActAsToken(receivedToken)) {
			// prevent an NPE within super.isDelegationAllowed
			// + we only want principal from OnBehalfOf token
			TokenDelegationResponse response = new TokenDelegationResponse();
			ReceivedToken delegateTarget = tokenParameters.getToken();
			response.setToken(delegateTarget);
			response.setDelegationAllowed(true);
			return response;
		}
		return super.isDelegationAllowed(tokenParameters);
	}

}
