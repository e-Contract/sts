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

import java.util.List;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.apache.ws.security.validate.Credential;
import org.apache.ws.security.validate.SamlAssertionValidator;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SAMLSamlAssertionValidator extends SamlAssertionValidator {

	private static final Logger LOGGER = LoggerFactory.getLogger(SAMLSamlAssertionValidator.class);

	public SAMLSamlAssertionValidator() {
		LOGGER.debug("constructor");
	}

	@Override
	public Credential validate(Credential credential, RequestData data) throws WSSecurityException {
		Credential result = super.validate(credential, data);
		AssertionWrapper assertionWrapper = credential.getAssertion();
		Assertion assertion = assertionWrapper.getSaml2();
		Subject subject = assertion.getSubject();
		List<SubjectConfirmation> subjectConfirmations = subject.getSubjectConfirmations();
		String recipient = null;
		for (SubjectConfirmation subjectConfirmation : subjectConfirmations) {
			String method = subjectConfirmation.getMethod();
			if (!SubjectConfirmation.METHOD_BEARER.equals(method)) {
				continue;
			}
			SubjectConfirmationData subjectConfirmationData = subjectConfirmation.getSubjectConfirmationData();
			if (null != subjectConfirmationData) {
				recipient = subjectConfirmationData.getRecipient();
				LOGGER.debug("recipient: {}", recipient);
			}
		}
		if (null == recipient) {
			throw new WSSecurityException("missing Recipient SubjectConfirmationData");
		}
		return result;
	}
}
