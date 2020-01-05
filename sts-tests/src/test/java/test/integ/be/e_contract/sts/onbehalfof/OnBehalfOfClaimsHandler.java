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

import java.net.URI;
import java.net.URISyntaxException;
import java.util.LinkedList;
import java.util.List;

import org.apache.cxf.sts.claims.Claim;
import org.apache.cxf.sts.claims.ClaimCollection;
import org.apache.cxf.sts.claims.ClaimsHandler;
import org.apache.cxf.sts.claims.ClaimsParameters;
import org.apache.cxf.sts.claims.RequestClaim;
import org.apache.cxf.sts.claims.RequestClaimCollection;
import org.apache.cxf.sts.request.ReceivedToken;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import be.e_contract.sts.ws.ClaimTypes;

public class OnBehalfOfClaimsHandler implements ClaimsHandler {

	private static final Logger LOGGER = LoggerFactory.getLogger(OnBehalfOfClaimsHandler.class);

	@Override
	public List<URI> getSupportedClaimTypes() {
		LOGGER.debug("getSupportedClaimTypes");
		List<URI> supportedClaimTypes = new LinkedList<>();
		try {
			supportedClaimTypes.add(new URI(ClaimTypes.SOFTWARE_KEY.getUri()));
			supportedClaimTypes.add(new URI(ClaimTypes.OFFICE_KEY.getUri()));
		} catch (URISyntaxException e) {
			throw new RuntimeException(e);
		}
		return supportedClaimTypes;
	}

	@Override
	public ClaimCollection retrieveClaimValues(RequestClaimCollection paramRequestClaimCollection,
			ClaimsParameters paramClaimsParameters) {
		LOGGER.debug("retrieveClaimValues");
		ClaimCollection claimCollection = new ClaimCollection();
		ReceivedToken actAsReceivedToken = paramClaimsParameters.getTokenRequirements().getActAs();
		String officeKey = null;
		String softwareKey = null;
		if (null != actAsReceivedToken) {
			LOGGER.debug("ActAs token available");
			Element tokenElement = (Element) actAsReceivedToken.getToken();
			AssertionWrapper assertionWrapper;
			try {
				assertionWrapper = new AssertionWrapper(tokenElement);
			} catch (WSSecurityException ex) {
				throw new RuntimeException("SAML parsing error: " + ex.getMessage(), ex);
			}
			Assertion assertion = assertionWrapper.getSaml2();
			List<AttributeStatement> attributeStatements = assertion.getAttributeStatements();
			AttributeStatement attributeStatement = attributeStatements.get(0);
			List<Attribute> attributes = attributeStatement.getAttributes();
			for (Attribute attribute : attributes) {
				String attributeName = attribute.getName();
				LOGGER.debug("attribute name: {}", attributeName);
				List<XMLObject> attributeValues = attribute.getAttributeValues();
				if (attributeValues.isEmpty()) {
					continue;
				}
				XMLObject attributeValue = attributeValues.get(0);
				if (attributeName.equals(ClaimTypes.OFFICE_KEY.getUri())) {
					if (!(attributeValue instanceof XSString)) {
						continue;
					}
					XSString stringAttributeValue = (XSString) attributeValue;
					officeKey = stringAttributeValue.getValue();
				} else if (attributeName.equals(ClaimTypes.SOFTWARE_KEY.getUri())) {
					if (!(attributeValue instanceof XSString)) {
						continue;
					}
					XSString stringAttributeValue = (XSString) attributeValue;
					softwareKey = stringAttributeValue.getValue();
				}
			}
		}
		for (RequestClaim requestClaim : paramRequestClaimCollection) {
			if (ClaimTypes.SOFTWARE_KEY.getUri().equals(requestClaim.getClaimType().toString())) {
				if (null == softwareKey) {
					throw new RuntimeException("missing ActAs software-key attribute");
				}
				Claim claim = new Claim();
				claim.setClaimType(requestClaim.getClaimType());
				claim.setPrincipal(paramClaimsParameters.getPrincipal());
				claim.addValue(softwareKey);
				claimCollection.add(claim);
			} else if (ClaimTypes.OFFICE_KEY.getUri().equals(requestClaim.getClaimType().toString())) {
				if (null == officeKey) {
					throw new RuntimeException("missing ActAs office-key attribute");
				}
				Claim claim = new Claim();
				claim.setClaimType(requestClaim.getClaimType());
				claim.setPrincipal(paramClaimsParameters.getPrincipal());
				claim.addValue(officeKey);
				claimCollection.add(claim);
			}
		}
		return claimCollection;
	}
}
