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
import org.apache.cxf.sts.request.ReceivedToken.STATE;
import org.apache.cxf.sts.token.validator.SAMLTokenValidator;
import org.apache.cxf.sts.token.validator.TokenValidatorParameters;
import org.apache.cxf.sts.token.validator.TokenValidatorResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

public class OnBehalfOfSAMLTokenValidator extends SAMLTokenValidator {

	private static final Logger LOGGER = LoggerFactory.getLogger(OnBehalfOfSAMLTokenValidator.class);

	@Override
	public boolean canHandleToken(ReceivedToken validateTarget) {
		LOGGER.debug("canHandleToken(validateTarget)");
		LOGGER.debug("token context: {}", validateTarget.getTokenContext());
		LOGGER.debug("received token: {}", validateTarget);
		boolean result = super.canHandleToken(validateTarget);
		LOGGER.debug("result: {}", result);
		return result;
	}

	@Override
	public boolean canHandleToken(ReceivedToken validateTarget, String realm) {
		LOGGER.debug("canHandleToken(validateTarget, realm)");
		LOGGER.debug("realm: {}", realm);
		boolean result = super.canHandleToken(validateTarget, realm);
		LOGGER.debug("result: {}", result);
		return result;
	}

	@Override
	public TokenValidatorResponse validateToken(TokenValidatorParameters tokenParameters) {
		LOGGER.debug("validateToken");
		LOGGER.debug("token context: {}", tokenParameters.getToken().getTokenContext());
		LOGGER.debug("ActAs: {}", tokenParameters.getTokenRequirements().getActAs() != null);
		LOGGER.debug("OnBehalfOf: {}", tokenParameters.getTokenRequirements().getOnBehalfOf() != null);
		LOGGER.debug("isActAsToken: {}", isActAsToken(tokenParameters));
		boolean isActAsToken = isActAsToken(tokenParameters);
		TokenValidatorResponse tokenValidatorResponse = super.validateToken(tokenParameters);
		if (isActAsToken) {
			tokenParameters.getToken().setState(STATE.VALID);
		}
		return tokenValidatorResponse;
	}

	private boolean isActAsToken(TokenValidatorParameters tokenParameters) {
		ReceivedToken receivedToken = tokenParameters.getToken();
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
}
