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

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.validate.Credential;
import org.apache.ws.security.validate.SamlAssertionValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ExampleSamlAssertionValidator extends SamlAssertionValidator {

	private static final Logger LOGGER = LoggerFactory
			.getLogger(ExampleSamlAssertionValidator.class);

	public ExampleSamlAssertionValidator() {
		LOGGER.debug("constructor");
	}

	@Override
	public Credential validate(Credential credential, RequestData data)
			throws WSSecurityException {
		return credential;
	}
}
