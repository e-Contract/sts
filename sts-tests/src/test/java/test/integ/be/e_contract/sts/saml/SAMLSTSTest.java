/*
 * eID Security Token Service Project.
 * Copyright (C) 2014-2019 e-Contract.be BVBA.
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

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.ws.Endpoint;

import org.apache.cxf.Bus;
import org.apache.cxf.BusFactory;
import org.apache.cxf.bus.spring.SpringBusFactory;
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
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import be.e_contract.sts.client.cxf.SAMLCallbackHandler;
import test.integ.be.e_contract.sts.ClientCrypto;
import test.integ.be.e_contract.sts.ExampleSecurityPolicyCallbackHandler;
import test.integ.be.e_contract.sts.ExampleSecurityTokenServiceProvider;
import test.integ.be.e_contract.sts.SecurityPolicyTest;

public class SAMLSTSTest {

	private static final Logger LOGGER = LoggerFactory.getLogger(SecurityPolicyTest.class);

	private Bus bus;

	private String stsUrl;

	private Endpoint stsEndpoint;

	private String samlStsUrl;

	private Endpoint samlStsEndpoint;

	@Before
	public void setUp() throws Exception {
		int sslFreePort = getFreePort();

		System.setProperty("testutil.ports.Server", Integer.toString(sslFreePort));

		SpringBusFactory bf = new SpringBusFactory();
		this.bus = bf.createBus("jaxws-server.xml");
		// NOT WORKING: jaxws-server-manager.xml
		// WORKING: jaxws-server.xml
		BusFactory.setDefaultBus(this.bus);

		this.stsUrl = "https://localhost:" + sslFreePort + "/example/sts";
		this.stsEndpoint = Endpoint.publish(this.stsUrl, new ExampleSecurityTokenServiceProvider());

		this.samlStsUrl = "https://localhost:" + sslFreePort + "/example/saml-sts";
		this.samlStsEndpoint = Endpoint.publish(this.samlStsUrl, new SAMLSecurityTokenServiceProvider());
	}

	@After
	public void tearDown() throws Exception {
		this.stsEndpoint.stop();
		this.samlStsEndpoint.stop();
	}

	@Test
	public void testSAMLSTS() throws Exception {
		LOGGER.debug("SAML STS test");

		SpringBusFactory bf = new SpringBusFactory();
		Bus bus = bf.createBus("cxf_https.xml");
		// NOT WORKING: cxf-https-trust-all.xml
		// WORKING: cxf_https.xml
		STSClient stsClient = new STSClient(bus);
		stsClient.setSoap12();
		stsClient.setWsdlLocation(this.stsUrl + "?wsdl");
		stsClient.setLocation(this.stsUrl);
		stsClient.setServiceName("{http://docs.oasis-open.org/ws-sx/ws-trust/200512}SecurityTokenService");
		stsClient.setEndpointName("{http://docs.oasis-open.org/ws-sx/ws-trust/200512}SecurityTokenServicePort");
		stsClient.setKeyType("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer");
		stsClient.setTokenType("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0");
		stsClient.setAllowRenewing(false);

		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();
		X509Certificate certificate = getCertificate(privateKey, publicKey);
		List<X509Certificate> certificates = new LinkedList<>();
		certificates.add(certificate);

		// Apache CXF specific configuration
		Map<String, Object> properties = stsClient.getProperties();
		properties.put(SecurityConstants.SIGNATURE_USERNAME, "username");
		properties.put(SecurityConstants.CALLBACK_HANDLER, new ExampleSecurityPolicyCallbackHandler());
		properties.put(SecurityConstants.SIGNATURE_CRYPTO, new ClientCrypto(privateKey, certificates));
		stsClient.setProperties(properties);

		SecurityToken securityToken = stsClient.requestSecurityToken("https://demo.app.applies.to");
		Element token = securityToken.getToken();
		LOGGER.debug("SAML token: {}", toString(token));

		// next we test the SAML STS
		stsClient = new STSClient(bus);
		stsClient.setSoap12();
		stsClient.setWsdlLocation(this.samlStsUrl + "?wsdl");
		stsClient.setLocation(this.samlStsUrl);
		stsClient.setServiceName("{http://docs.oasis-open.org/ws-sx/ws-trust/200512}SecurityTokenService");
		stsClient.setEndpointName("{http://docs.oasis-open.org/ws-sx/ws-trust/200512}SecurityTokenServicePort");
		stsClient.setTokenType("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0");
		stsClient.setKeyType("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer");
		properties = stsClient.getProperties();
		properties.put(SecurityConstants.SAML_CALLBACK_HANDLER, new SAMLCallbackHandler(token));
		stsClient.setProperties(properties);
		securityToken = stsClient.requestSecurityToken();
		token = securityToken.getToken();
		LOGGER.debug("STS SAML token: {}", toString(token));
	}

	private static int getFreePort() throws Exception {
		try (ServerSocket serverSocket = new ServerSocket(0)) {
			return serverSocket.getLocalPort();
		}
	}

	private static X509Certificate getCertificate(PrivateKey privateKey, PublicKey publicKey) throws Exception {
		X500Name subjectName = new X500Name("CN=Test");
		X500Name issuerName = subjectName; // self-signed
		BigInteger serial = new BigInteger(128, new SecureRandom());
		SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(issuerName, serial,
				notBefore.toDate(), notAfter.toDate(), subjectName, publicKeyInfo);
		AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1withRSA");
		AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
		AsymmetricKeyParameter asymmetricKeyParameter = PrivateKeyFactory.createKey(privateKey.getEncoded());

		ContentSigner contentSigner = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(asymmetricKeyParameter);
		X509CertificateHolder x509CertificateHolder = x509v3CertificateBuilder.build(contentSigner);

		byte[] encodedCertificate = x509CertificateHolder.getEncoded();

		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		X509Certificate certificate = (X509Certificate) certificateFactory
				.generateCertificate(new ByteArrayInputStream(encodedCertificate));
		return certificate;
	}

	private static String toString(Node node) throws Exception {
		TransformerFactory transformerFactory = TransformerFactory.newInstance();
		Transformer transformer = transformerFactory.newTransformer();
		StringWriter stringWriter = new StringWriter();
		transformer.transform(new DOMSource(node), new StreamResult(stringWriter));
		return stringWriter.toString();
	}
}
