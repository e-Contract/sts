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
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.xml.ws.BindingProvider;
import javax.xml.ws.soap.SOAPFaultException;

import org.apache.cxf.Bus;
import org.apache.cxf.BusFactory;
import org.apache.cxf.ws.security.SecurityConstants;
import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.apache.cxf.ws.security.trust.STSClient;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.e_contract.sts.example.ws.jaxws.ExampleService;
import be.e_contract.sts.example.ws.jaxws.ExampleServicePortType;
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

		// STS based validation
		stsClient.setEnableAppliesTo(true);
		stsClient
				.setTokenType("http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/Status");
		List<SecurityToken> result = stsClient
				.validateSecurityToken(securityToken);
		assertEquals(1, result.size());
		SecurityToken resultSecurityToken = result.get(0);
		LOGGER.debug("token type: {}", resultSecurityToken.getTokenType());
		assertEquals(
				"http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0",
				resultSecurityToken.getTokenType());
	}

	/**
	 * Requires a patched version of Apache CXF. See also:
	 * 
	 * https://issues.apache.org/jira/browse/CXF-6110
	 * 
	 * @throws Exception
	 */
	@Test
	public void testExampleWebService() throws Exception {
		ExampleService exampleService = new ExampleService();
		ExampleServicePortType port = exampleService.getExampleServicePort();

		BindingProvider bindingProvider = (BindingProvider) port;
		Map<String, Object> requestContext = bindingProvider
				.getRequestContext();
		requestContext.put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY,
				"https://www.e-contract.be/iam/example");

		requestContext.put(SecurityConstants.STS_CLIENT_SOAP12_BINDING, "true");
		requestContext
				.put(SecurityConstants.SIGNATURE_CRYPTO, new BeIDCrypto());
		requestContext.put(SecurityConstants.SIGNATURE_USERNAME, "username");
		requestContext.put(SecurityConstants.CALLBACK_HANDLER,
				new ExampleSecurityPolicyCallbackHandler());
		requestContext.put(
				SecurityConstants.PREFER_WSMEX_OVER_STS_CLIENT_CONFIG, "true");

		String result = port.echo("hello world");
		LOGGER.debug("result: " + result);
	}

	@Test
	public void testSelfSignedCertificateFails() throws Exception {
		ExampleService exampleService = new ExampleService();
		ExampleServicePortType port = exampleService.getExampleServicePort();

		// set the web service address on the client stub
		BindingProvider bindingProvider = (BindingProvider) port;
		Map<String, Object> requestContext = bindingProvider
				.getRequestContext();
		requestContext.put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY,
				"https://www.e-contract.be/iam/example");

		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();
		X509Certificate certificate = getCertificate(privateKey, publicKey);
		List<X509Certificate> certificates = new LinkedList<X509Certificate>();
		certificates.add(certificate);

		requestContext.put(SecurityConstants.STS_CLIENT_SOAP12_BINDING, "true");
		requestContext.put(SecurityConstants.SIGNATURE_CRYPTO,
				new ClientCrypto(privateKey, certificates));
		requestContext.put(SecurityConstants.STS_TOKEN_USE_CERT_FOR_KEYINFO,
				"true");
		requestContext.put(SecurityConstants.SIGNATURE_USERNAME, "username");
		requestContext.put(SecurityConstants.CALLBACK_HANDLER,
				new ExampleSecurityPolicyCallbackHandler());
		requestContext.put(
				SecurityConstants.PREFER_WSMEX_OVER_STS_CLIENT_CONFIG, "true");

		// invoke the web service
		try {
			port.echo("hello world");
			fail();
		} catch (SOAPFaultException e) {
			// expected
			assertTrue(e.getMessage().contains("security token"));
		}
	}

	private static X509Certificate getCertificate(PrivateKey privateKey,
			PublicKey publicKey) throws Exception {
		X500Name subjectName = new X500Name("CN=Test");
		X500Name issuerName = subjectName; // self-signed
		BigInteger serial = new BigInteger(128, new SecureRandom());
		SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo
				.getInstance(publicKey.getEncoded());
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(
				issuerName, serial, notBefore.toDate(), notAfter.toDate(),
				subjectName, publicKeyInfo);
		AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder()
				.find("SHA1withRSA");
		AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder()
				.find(sigAlgId);
		AsymmetricKeyParameter asymmetricKeyParameter = PrivateKeyFactory
				.createKey(privateKey.getEncoded());

		ContentSigner contentSigner = new BcRSAContentSignerBuilder(sigAlgId,
				digAlgId).build(asymmetricKeyParameter);
		X509CertificateHolder x509CertificateHolder = x509v3CertificateBuilder
				.build(contentSigner);

		byte[] encodedCertificate = x509CertificateHolder.getEncoded();

		CertificateFactory certificateFactory = CertificateFactory
				.getInstance("X.509");
		X509Certificate certificate = (X509Certificate) certificateFactory
				.generateCertificate(new ByteArrayInputStream(
						encodedCertificate));
		return certificate;
	}
}
