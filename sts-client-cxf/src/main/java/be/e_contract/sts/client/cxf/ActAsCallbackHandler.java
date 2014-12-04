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

package be.e_contract.sts.client.cxf;

import java.io.IOException;
import java.util.List;
import java.util.UUID;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.namespace.QName;

import org.apache.cxf.ws.security.trust.delegation.DelegationCallback;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.schema.XSString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

/**
 * JAAS callback for Apache CXF ActAs token construction.
 * 
 * @author Frank Cornelis
 *
 */
public class ActAsCallbackHandler implements CallbackHandler {

	private static final Logger LOGGER = LoggerFactory
			.getLogger(ActAsCallbackHandler.class);

	private final String officeKey;

	private final String softwareKey;

	public ActAsCallbackHandler(String officeKey, String softwareKey) {
		this.officeKey = officeKey;
		this.softwareKey = softwareKey;
	}

	static {
		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public void handle(Callback[] callbacks) throws IOException,
			UnsupportedCallbackException {
		for (Callback callback : callbacks) {
			LOGGER.debug("callback type: {}", callback.getClass().getName());
			if (callback instanceof DelegationCallback) {
				DelegationCallback delegationCallback = (DelegationCallback) callback;
				Element tokenElement;
				try {
					tokenElement = getTokenElement();
				} catch (Exception e) {
					throw new IOException(e);
				}
				delegationCallback.setToken(tokenElement);
			}
		}
	}

	private Element getTokenElement() throws Exception {
		Assertion assertion = buildXMLObject(Assertion.class,
				Assertion.DEFAULT_ELEMENT_NAME);
		assertion.setVersion(SAMLVersion.VERSION_20);
		String assertionId = "assertion-" + UUID.randomUUID().toString();
		assertion.setID(assertionId);
		DateTime issueInstant = new DateTime();
		assertion.setIssueInstant(issueInstant);

		Issuer issuer = buildXMLObject(Issuer.class,
				Issuer.DEFAULT_ELEMENT_NAME);
		assertion.setIssuer(issuer);
		issuer.setValue("self-claimed");

		List<AttributeStatement> attributeStatements = assertion
				.getAttributeStatements();
		AttributeStatement attributeStatement = buildXMLObject(
				AttributeStatement.class,
				AttributeStatement.DEFAULT_ELEMENT_NAME);
		attributeStatements.add(attributeStatement);

		XMLObjectBuilder<XSString> builder = Configuration.getBuilderFactory()
				.getBuilder(XSString.TYPE_NAME);

		Attribute softwareKeyAttribute = buildXMLObject(Attribute.class,
				Attribute.DEFAULT_ELEMENT_NAME);
		softwareKeyAttribute
				.setName("urn:be:e-contract:iam:claims:self-claimed:software-key");
		XSString softwareKeyAttributeValue = builder.buildObject(
				AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
		softwareKeyAttributeValue.setValue(this.softwareKey);
		softwareKeyAttribute.getAttributeValues()
				.add(softwareKeyAttributeValue);
		attributeStatement.getAttributes().add(softwareKeyAttribute);

		Attribute officeKeyAttribute = buildXMLObject(Attribute.class,
				Attribute.DEFAULT_ELEMENT_NAME);
		officeKeyAttribute
				.setName("urn:be:e-contract:iam:claims:self-claimed:office-key");
		XSString officeKeyAttributeValue = builder.buildObject(
				AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
		officeKeyAttributeValue.setValue(this.officeKey);
		officeKeyAttribute.getAttributeValues().add(officeKeyAttributeValue);
		attributeStatement.getAttributes().add(officeKeyAttribute);

		Element element = Configuration.getMarshallerFactory()
				.getMarshaller(assertion).marshall(assertion);
		return element;
	}

	private <T extends XMLObject> T buildXMLObject(Class<T> clazz,
			QName objectQName) {
		XMLObjectBuilder<T> builder = Configuration.getBuilderFactory()
				.getBuilder(objectQName);
		if (builder == null) {
			throw new RuntimeException(
					"Unable to retrieve builder for object QName "
							+ objectQName);
		}
		return builder.buildObject(objectQName);
	}
}
