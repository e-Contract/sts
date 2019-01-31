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

package test.integ.be.e_contract.sts.onbehalfof;

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Map;

import javax.xml.transform.OutputKeys;
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
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.keyinfo.KeyInfoGenerator;
import org.opensaml.xml.security.keyinfo.KeyInfoGeneratorFactory;
import org.opensaml.xml.security.keyinfo.KeyInfoGeneratorManager;
import org.opensaml.xml.security.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.impl.SignatureBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import test.integ.be.e_contract.sts.ClientCrypto;
import test.integ.be.e_contract.sts.ExampleSecurityPolicyCallbackHandler;

public class OnBehalfOfTest {

	private static final Logger LOGGER = LoggerFactory.getLogger(OnBehalfOfTest.class);

	private static final X509Certificate SAML_SIGNER_CERTIFICATE;

	private static final PrivateKey SAML_SIGNER_PRIVATE_KEY;

	private static final X509Certificate WS_SECURITY_SIGNER_CERTIFICATE;

	private static final PrivateKey WS_SECURITY_SIGNER_PRIVATE_KEY;

	private Bus bus;

	private String stsUrl;

	private Endpoint stsEndpoint;

	static {
		KeyPairGenerator keyPairGenerator;
		try {
			keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
		KeyPair samlKeyPair = keyPairGenerator.generateKeyPair();
		SAML_SIGNER_PRIVATE_KEY = samlKeyPair.getPrivate();
		PublicKey samlPublicKey = samlKeyPair.getPublic();
		try {
			SAML_SIGNER_CERTIFICATE = getCertificate("CN=PassiveIdentityProvider", SAML_SIGNER_PRIVATE_KEY,
					samlPublicKey);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}

		try {
			keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
		KeyPair wsSecurityKeyPair = keyPairGenerator.generateKeyPair();
		WS_SECURITY_SIGNER_PRIVATE_KEY = wsSecurityKeyPair.getPrivate();
		PublicKey wsSecurityPublicKey = wsSecurityKeyPair.getPublic();
		try {
			WS_SECURITY_SIGNER_CERTIFICATE = getCertificate("CN=PassiveIdentityProvider", SAML_SIGNER_PRIVATE_KEY,
					wsSecurityPublicKey);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Before
	public void setUp() throws Exception {
		int sslFreePort = getFreePort();
		System.setProperty("testutil.ports.Server", Integer.toString(sslFreePort));

		SpringBusFactory bf = new SpringBusFactory();
		this.bus = bf.createBus("jaxws-server-manager.xml");
		BusFactory.setDefaultBus(this.bus);

		this.stsUrl = "https://localhost:" + sslFreePort + "/example/sts";
		this.stsEndpoint = Endpoint.publish(this.stsUrl, new OnBehalfOfSecurityTokenServiceProvider());
	}

	@After
	public void tearDown() throws Exception {
		this.stsEndpoint.stop();
	}

	@Test
	public void testOnBehalfOf() throws Exception {
		Element onBehalfOfToken = generateToken();
		LOGGER.debug("OnBehalfOf SAML token: {}", toFormattedString(onBehalfOfToken));

		SpringBusFactory bf = new SpringBusFactory();
		Bus bus = bf.createBus("cxf-https-trust-all.xml");
		STSClient stsClient = new STSClient(bus);
		stsClient.setSoap12();
		stsClient.setWsdlLocation(this.stsUrl + "?wsdl");
		stsClient.setLocation(this.stsUrl);
		stsClient.setServiceName("{http://docs.oasis-open.org/ws-sx/ws-trust/200512}SecurityTokenService");
		stsClient.setEndpointName("{http://docs.oasis-open.org/ws-sx/ws-trust/200512}SecurityTokenServicePort");
		stsClient.setTokenType("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0");
		stsClient.setKeyType("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer");
		Map<String, Object> properties = stsClient.getProperties();
		properties.put(SecurityConstants.SIGNATURE_USERNAME, "username");
		properties.put(SecurityConstants.CALLBACK_HANDLER, new ExampleSecurityPolicyCallbackHandler());
		properties.put(SecurityConstants.SIGNATURE_CRYPTO,
				new ClientCrypto(WS_SECURITY_SIGNER_PRIVATE_KEY, WS_SECURITY_SIGNER_CERTIFICATE));
		stsClient.setProperties(properties);
		stsClient.setOnBehalfOf(onBehalfOfToken);
		stsClient.setEnableLifetime(true);
		stsClient.setTtl(60 * 60 * 5);
		SecurityToken securityToken = stsClient.requestSecurityToken("http://active.saml.token.target");
		Element token = securityToken.getToken();
		LOGGER.debug("STS SAML token: {}", toFormattedString(token));
	}

	@Test
	public void testOnBehalfOfNoAppliesTo() throws Exception {
		Element onBehalfOfToken = generateToken();
		LOGGER.debug("OnBehalfOf SAML token: {}", toFormattedString(onBehalfOfToken));

		SpringBusFactory bf = new SpringBusFactory();
		Bus bus = bf.createBus("cxf-https-trust-all.xml");
		STSClient stsClient = new STSClient(bus);
		stsClient.setSoap12();
		stsClient.setWsdlLocation(this.stsUrl + "?wsdl");
		stsClient.setLocation(this.stsUrl);
		stsClient.setServiceName("{http://docs.oasis-open.org/ws-sx/ws-trust/200512}SecurityTokenService");
		stsClient.setEndpointName("{http://docs.oasis-open.org/ws-sx/ws-trust/200512}SecurityTokenServicePort");
		stsClient.setTokenType("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0");
		stsClient.setKeyType("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer");
		Map<String, Object> properties = stsClient.getProperties();
		properties.put(SecurityConstants.SIGNATURE_USERNAME, "username");
		properties.put(SecurityConstants.CALLBACK_HANDLER, new ExampleSecurityPolicyCallbackHandler());
		properties.put(SecurityConstants.SIGNATURE_CRYPTO,
				new ClientCrypto(WS_SECURITY_SIGNER_PRIVATE_KEY, WS_SECURITY_SIGNER_CERTIFICATE));
		stsClient.setProperties(properties);
		stsClient.setOnBehalfOf(onBehalfOfToken);
		stsClient.setEnableLifetime(true);
		stsClient.setTtl(60 * 60 * 5);
		SecurityToken securityToken = stsClient.requestSecurityToken();
		Element token = securityToken.getToken();
		LOGGER.debug("STS SAML token: {}", toFormattedString(token));
	}

	@Test
	public void testOnBehalfOfHOK() throws Exception {
		Element onBehalfOfToken = generateToken();
		LOGGER.debug("OnBehalfOf SAML token: {}", toFormattedString(onBehalfOfToken));

		SpringBusFactory bf = new SpringBusFactory();
		Bus bus = bf.createBus("cxf-https-trust-all.xml");
		STSClient stsClient = new STSClient(bus);
		stsClient.setSoap12();
		stsClient.setWsdlLocation(this.stsUrl + "?wsdl");
		stsClient.setLocation(this.stsUrl);
		stsClient.setServiceName("{http://docs.oasis-open.org/ws-sx/ws-trust/200512}SecurityTokenService");
		stsClient.setEndpointName("{http://docs.oasis-open.org/ws-sx/ws-trust/200512}SecurityTokenServicePort");
		stsClient.setTokenType("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0");
		stsClient.setKeyType("http://docs.oasis-open.org/ws-sx/ws-trust/200512/PublicKey");
		Map<String, Object> properties = stsClient.getProperties();
		properties.put(SecurityConstants.SIGNATURE_USERNAME, "username");
		properties.put(SecurityConstants.CALLBACK_HANDLER, new ExampleSecurityPolicyCallbackHandler());
		properties.put(SecurityConstants.SIGNATURE_CRYPTO,
				new ClientCrypto(WS_SECURITY_SIGNER_PRIVATE_KEY, WS_SECURITY_SIGNER_CERTIFICATE));
		// holder of key
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		KeyPair hokKeyPair = keyPairGenerator.generateKeyPair();
		PrivateKey hokPrivateKey = hokKeyPair.getPrivate();
		PublicKey hokPublicKey = hokKeyPair.getPublic();
		X509Certificate hokCertificate = getCertificate("CN=HOK", hokPrivateKey, hokPublicKey);
		properties.put(SecurityConstants.STS_TOKEN_CRYPTO, new ClientCrypto(hokPrivateKey, hokCertificate));
		stsClient.setProperties(properties);
		stsClient.setOnBehalfOf(onBehalfOfToken);
		stsClient.setEnableLifetime(true);
		stsClient.setTtl(600);
		SecurityToken securityToken = stsClient.requestSecurityToken("http://active.saml.token.target");
		Element token = securityToken.getToken();
		LOGGER.debug("STS SAML token: {}", toFormattedString(token));

	}

	private static int getFreePort() throws Exception {
		try (ServerSocket serverSocket = new ServerSocket(0)) {
			return serverSocket.getLocalPort();
		}
	}

	private Element generateToken() throws Exception {
		DefaultBootstrap.bootstrap();
		XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
		SAMLObjectBuilder<Assertion> assertionBuilder = (SAMLObjectBuilder<Assertion>) builderFactory
				.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
		Assertion assertion = assertionBuilder.buildObject();
		assertion.setID("saml-id");

		SAMLObjectBuilder<Subject> subjectBuilder = (SAMLObjectBuilder<Subject>) builderFactory
				.getBuilder(Subject.DEFAULT_ELEMENT_NAME);
		Subject subject = subjectBuilder.buildObject();
		SAMLObjectBuilder<NameID> nameIDBuilder = (SAMLObjectBuilder<NameID>) builderFactory
				.getBuilder(NameID.DEFAULT_ELEMENT_NAME);
		NameID nameID = nameIDBuilder.buildObject();
		nameID.setValue("subject");
		subject.setNameID(nameID);
		SAMLObjectBuilder<SubjectConfirmation> subjectConfirmationBuilder = (SAMLObjectBuilder<SubjectConfirmation>) builderFactory
				.getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
		SubjectConfirmation subjectConfirmation = subjectConfirmationBuilder.buildObject();
		subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);
		SAMLObjectBuilder<SubjectConfirmationData> subjectConfirmationDataBuilder = (SAMLObjectBuilder<SubjectConfirmationData>) builderFactory
				.getBuilder(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
		SubjectConfirmationData subjectConfirmationData = subjectConfirmationDataBuilder.buildObject();
		subjectConfirmationData.setRecipient("recipient");
		subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
		subject.getSubjectConfirmations().add(subjectConfirmation);
		assertion.setSubject(subject);

		SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory
				.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
		Issuer issuer = issuerBuilder.buildObject();
		issuer.setValue("passive-saml-issuer");
		assertion.setIssuer(issuer);

		DateTime issueInstance = new DateTime();
		assertion.setIssueInstant(issueInstance);

		SAMLObjectBuilder<Conditions> conditionsBuilder = (SAMLObjectBuilder<Conditions>) builderFactory
				.getBuilder(Conditions.DEFAULT_ELEMENT_NAME);
		Conditions conditions = conditionsBuilder.buildObject();
		conditions.setNotBefore(issueInstance);
		DateTime notAfter = issueInstance.plusMinutes(5);
		conditions.setNotOnOrAfter(notAfter);
		assertion.setConditions(conditions);

		SignatureBuilder signatureBuilder = new SignatureBuilder();
		Signature signature = signatureBuilder.buildObject();
		BasicX509Credential credential = new BasicX509Credential();
		credential.setPrivateKey(SAML_SIGNER_PRIVATE_KEY);
		credential.setEntityCertificate(SAML_SIGNER_CERTIFICATE);
		signature.setSigningCredential(credential);
		signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
		signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		SecurityConfiguration secConfiguration = Configuration.getGlobalSecurityConfiguration();
		NamedKeyInfoGeneratorManager namedKeyInfoGeneratorManager = secConfiguration.getKeyInfoGeneratorManager();
		KeyInfoGeneratorManager keyInfoGeneratorManager = namedKeyInfoGeneratorManager.getDefaultManager();
		KeyInfoGeneratorFactory keyInfoGeneratorFactory = keyInfoGeneratorManager.getFactory(credential);
		KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();
		KeyInfo keyInfo = keyInfoGenerator.generate(credential);
		signature.setKeyInfo(keyInfo);
		assertion.setSignature(signature);

		MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
		Marshaller marshaller = marshallerFactory.getMarshaller(assertion);
		Element token = marshaller.marshall(assertion);

		Signer.signObject(signature);

		return token;
	}

	public static X509Certificate getSAMLSignerCertificate() {
		return SAML_SIGNER_CERTIFICATE;
	}

	private static X509Certificate getCertificate(String name, PrivateKey privateKey, PublicKey publicKey)
			throws Exception {
		X500Name subjectName = new X500Name(name);
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

	private static String toFormattedString(Node node) throws Exception {
		TransformerFactory transformerFactory = TransformerFactory.newInstance();
		Transformer transformer = transformerFactory.newTransformer();
		transformer.setOutputProperty(OutputKeys.INDENT, "yes");
		transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
		StringWriter stringWriter = new StringWriter();
		transformer.transform(new DOMSource(node), new StreamResult(stringWriter));
		return stringWriter.toString();
	}
}
