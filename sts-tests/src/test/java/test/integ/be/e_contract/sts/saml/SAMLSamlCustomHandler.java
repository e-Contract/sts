/*
 * eID Security Token Service Project.
 * Copyright (C) 2019 e-Contract.be BVBA.
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

package test.integ.be.e_contract.sts.saml;

import org.apache.cxf.sts.token.provider.SamlCustomHandler;
import org.apache.cxf.sts.token.provider.TokenProviderParameters;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SAMLSamlCustomHandler implements SamlCustomHandler {

	private static final Logger LOGGER = LoggerFactory.getLogger(SAMLSamlCustomHandler.class);

	@Override
	public void handle(AssertionWrapper assertionWrapper, TokenProviderParameters tokenParameters) {
		LOGGER.debug("handle");
		LOGGER.debug("applies to address: {}", tokenParameters.getAppliesToAddress());
	}
}
