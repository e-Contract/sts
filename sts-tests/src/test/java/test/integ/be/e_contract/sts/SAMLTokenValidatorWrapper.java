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
import org.apache.cxf.sts.token.validator.SAMLTokenValidator;
import org.apache.cxf.sts.token.validator.TokenValidator;
import org.apache.cxf.sts.token.validator.TokenValidatorParameters;
import org.apache.cxf.sts.token.validator.TokenValidatorResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Just to visualize the exceptions thrown.
 * 
 * @author fcorneli
 *
 */
public class SAMLTokenValidatorWrapper implements TokenValidator {

	private static final Logger LOGGER = LoggerFactory
			.getLogger(SAMLTokenValidatorWrapper.class);

	private final SAMLTokenValidator samlTokenValidator;

	public SAMLTokenValidatorWrapper(SAMLTokenValidator samlTokenValidator) {
		this.samlTokenValidator = samlTokenValidator;
	}

	@Override
	public boolean canHandleToken(ReceivedToken validateTarget) {
		return this.samlTokenValidator.canHandleToken(validateTarget);
	}

	@Override
	public boolean canHandleToken(ReceivedToken validateTarget, String realm) {
		return this.samlTokenValidator.canHandleToken(validateTarget, realm);
	}

	@Override
	public TokenValidatorResponse validateToken(
			TokenValidatorParameters tokenParameters) {
		try {
			return this.samlTokenValidator.validateToken(tokenParameters);
		} catch (Exception e) {
			LOGGER.error("validation error", e);
			throw e;
		}
	}
}
