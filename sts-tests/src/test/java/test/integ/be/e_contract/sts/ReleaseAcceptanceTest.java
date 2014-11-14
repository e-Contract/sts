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

import static org.junit.Assert.assertEquals;

import java.security.Principal;
import java.security.Security;
import java.util.Map;

import org.apache.cxf.Bus;
import org.apache.cxf.BusFactory;
import org.apache.cxf.ws.security.SecurityConstants;
import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.apache.cxf.ws.security.trust.STSClient;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.fedict.commons.eid.jca.BeIDProvider;

/**
 * The acceptance tests for a release of the IAM platform. All these acceptance
 * tests should pass.
 * 
 * @author Frank Cornelis
 *
 */
public class ReleaseAcceptanceTest {

	private static final Logger LOGGER = LoggerFactory
			.getLogger(ReleaseAcceptanceTest.class);

	private static final String STS_LOCATION = "https://www.e-contract.be/iam/sts";

	@Before
	public void setUp() throws Exception {
		Security.addProvider(new BeIDProvider());
	}

	@Test
	public void testIssueSAMLBearerToken() throws Exception {
		Bus bus = BusFactory.getDefaultBus();
		STSClient stsClient = new STSClient(bus);
		stsClient.setSoap12();
		stsClient.setWsdlLocation(STS_LOCATION + "?wsdl");
		stsClient.setLocation(STS_LOCATION);
		stsClient
				.setServiceName("{http://docs.oasis-open.org/ws-sx/ws-trust/200512}SecurityTokenService");
		stsClient
				.setEndpointName("{http://docs.oasis-open.org/ws-sx/ws-trust/200512}SecurityTokenServicePort");
		stsClient
				.setKeyType("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer");
		stsClient
				.setTokenType("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0");
		stsClient.setAllowRenewing(false);

		// Apache CXF specific configuration
		Map<String, Object> properties = stsClient.getProperties();
		properties.put(SecurityConstants.SIGNATURE_USERNAME, "username");
		properties.put(SecurityConstants.CALLBACK_HANDLER,
				new ExampleSecurityPolicyCallbackHandler());
		properties.put(SecurityConstants.SIGNATURE_CRYPTO, new BeIDCrypto());
		stsClient.setProperties(properties);

		LOGGER.debug("STS location: {}", stsClient.getLocation());
		SecurityToken securityToken = stsClient
				.requestSecurityToken("https://demo.app.applies.to");
		Principal principal = securityToken.getPrincipal();
		LOGGER.debug("principal: {}", principal);
		LOGGER.debug("token type: {}", securityToken.getTokenType());
		assertEquals(
				"http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0",
				securityToken.getTokenType());
		LOGGER.debug("security token expires: {}", securityToken.getExpires());
	}
}
