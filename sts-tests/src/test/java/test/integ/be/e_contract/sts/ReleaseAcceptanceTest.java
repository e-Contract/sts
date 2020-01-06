/*
 * eID Security Token Service Project.
 * Copyright (C) 2014-2020 e-Contract.be BVBA.
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
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.ws.Binding;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.handler.Handler;
import javax.xml.ws.soap.SOAPFaultException;

import org.apache.commons.io.FileUtils;
import org.apache.cxf.Bus;
import org.apache.cxf.BusFactory;
import org.apache.cxf.bus.spring.SpringBusFactory;
import org.apache.cxf.helpers.DOMUtils;
import org.apache.cxf.ws.security.SecurityConstants;
import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.apache.cxf.ws.security.trust.STSClient;
import org.apache.ws.security.saml.ext.AssertionWrapper;
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
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.keyinfo.KeyInfoGenerator;
import org.opensaml.xml.security.keyinfo.KeyInfoGeneratorFactory;
import org.opensaml.xml.security.keyinfo.KeyInfoGeneratorManager;
import org.opensaml.xml.security.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.impl.SignatureBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import be.e_contract.sts.client.cxf.SecurityDecorator;
import be.e_contract.sts.example.ws.jaxb.BearerRequest;
import be.e_contract.sts.example.ws.jaxb.ClaimType;
import be.e_contract.sts.example.ws.jaxb.ClaimsResponseType;
import be.e_contract.sts.example.ws.jaxb.GetAddressClaimsRequest;
import be.e_contract.sts.example.ws.jaxb.GetIdentityClaimsRequest;
import be.e_contract.sts.example.ws.jaxb.GetSelfClaimsRequest;
import be.e_contract.sts.example.ws.jaxws.ExampleService;
import be.e_contract.sts.example.ws.jaxws.ExampleServicePortType;
import be.fedict.commons.eid.client.BeIDCard;
import be.fedict.commons.eid.client.BeIDCards;
import be.fedict.commons.eid.client.FileType;
import be.fedict.commons.eid.jca.BeIDProvider;
import test.integ.be.e_contract.sts.onbehalfof.TestOnBehalfOfService;

/**
 * The acceptance tests for a release of the IAM platform. All these acceptance
 * tests should pass.
 * 
 * @author Frank Cornelis
 * 
 */
public class ReleaseAcceptanceTest {

	private static final Logger LOGGER = LoggerFactory.getLogger(ReleaseAcceptanceTest.class);

	private static final String STS_LOCATION = "https://local.e-contract.be/iam/sts";
	private static final String ONBEHALFOF_STS_LOCATION = "https://local.e-contract.be/iam/onbehalfof-sts";

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
		stsClient.setServiceName("{http://docs.oasis-open.org/ws-sx/ws-trust/200512}SecurityTokenService");
		stsClient.setEndpointName("{http://docs.oasis-open.org/ws-sx/ws-trust/200512}SecurityTokenServicePort");
		stsClient.setKeyType("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer");
		stsClient.setTokenType("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0");
		stsClient.setAllowRenewing(false);

		// Apache CXF specific configuration
		Map<String, Object> properties = stsClient.getProperties();
		properties.put(SecurityConstants.SIGNATURE_USERNAME, "username");
		properties.put(SecurityConstants.CALLBACK_HANDLER, new ExampleSecurityPolicyCallbackHandler());
		properties.put(SecurityConstants.SIGNATURE_CRYPTO, new BeIDCrypto());
		stsClient.setProperties(properties);

		LOGGER.debug("STS location: {}", stsClient.getLocation());
		SecurityToken securityToken = stsClient.requestSecurityToken("https://www.e-contract.be/iam/example");
		Principal principal = securityToken.getPrincipal();
		LOGGER.debug("principal: {}", principal);
		LOGGER.debug("token type: {}", securityToken.getTokenType());
		assertEquals("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0",
				securityToken.getTokenType());
		LOGGER.debug("security token expires: {}", securityToken.getExpires());

		// STS based validation
		stsClient.setEnableAppliesTo(true);
		stsClient.setTokenType("http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/Status");
		List<SecurityToken> result = stsClient.validateSecurityToken(securityToken);
		assertEquals(1, result.size());
		SecurityToken resultSecurityToken = result.get(0);
		LOGGER.debug("token type: {}", resultSecurityToken.getTokenType());
		assertEquals("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0",
				resultSecurityToken.getTokenType());

		// use the SAML bearer token directly.
		ExampleService exampleService = new ExampleService();
		ExampleServicePortType port = exampleService.getExampleServicePort();
		SecurityDecorator securityDecorator = new SecurityDecorator();
		securityDecorator.decorate((BindingProvider) port, resultSecurityToken.getToken(),
				"https://www.e-contract.be/iam/example");

		BearerRequest bearerRequest = new BearerRequest();
		ClaimsResponseType response = port.bearer(bearerRequest);
		LOGGER.debug("subject: {}", response.getSubject());
		for (ClaimType claim : response.getClaim()) {
			LOGGER.debug("claim {} = {}", claim.getName(), claim.getValue());
		}
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
		Map<String, Object> requestContext = bindingProvider.getRequestContext();
		requestContext.put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, "https://www.e-contract.be/iam/example");

		requestContext.put(SecurityConstants.STS_CLIENT_SOAP12_BINDING, "true");
		requestContext.put(SecurityConstants.SIGNATURE_CRYPTO, new BeIDCrypto());
		requestContext.put(SecurityConstants.SIGNATURE_USERNAME, "username");
		requestContext.put(SecurityConstants.CALLBACK_HANDLER, new ExampleSecurityPolicyCallbackHandler());
		requestContext.put(SecurityConstants.PREFER_WSMEX_OVER_STS_CLIENT_CONFIG, "true");

		String result = port.echo("hello world");
		LOGGER.debug("result: " + result);
	}

	@Test
	public void testExampleWebServiceWithClaimsAndActAsToken() throws Exception {
		ExampleService exampleService = new ExampleService();
		ExampleServicePortType port = exampleService.getExampleServicePort();

		// set the web service address on the client stub
		BindingProvider bindingProvider = (BindingProvider) port;
		Map<String, Object> requestContext = bindingProvider.getRequestContext();
		requestContext.put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, "https://www.e-contract.be/iam/example");

		requestContext.put(SecurityConstants.STS_CLIENT_SOAP12_BINDING, "true");
		requestContext.put(SecurityConstants.SIGNATURE_CRYPTO, new BeIDCrypto());
		requestContext.put(SecurityConstants.STS_TOKEN_USE_CERT_FOR_KEYINFO, "true");
		requestContext.put(SecurityConstants.SIGNATURE_USERNAME, "username");
		requestContext.put(SecurityConstants.CALLBACK_HANDLER, new ExampleSecurityPolicyCallbackHandler());
		requestContext.put(SecurityConstants.PREFER_WSMEX_OVER_STS_CLIENT_CONFIG, "true");
		requestContext.put(SecurityConstants.STS_TOKEN_ACT_AS,
				new ActAsSamlCallbackHandler("example-office-key", "example-software-key"));

		// invoke the web service
		GetSelfClaimsRequest getSelfClaimsRequest = new GetSelfClaimsRequest();
		ClaimsResponseType claimsResponse = port.getSelfClaims(getSelfClaimsRequest);
		LOGGER.debug("subject: {}", claimsResponse.getSubject());
		for (ClaimType claim : claimsResponse.getClaim()) {
			LOGGER.debug("claim {} = {}", claim.getName(), claim.getValue());
		}
		assertTrue(hasClaim(claimsResponse.getClaim(), "urn:be:e-contract:iam:claims:self-claimed:office-key",
				"example-office-key"));
		assertTrue(hasClaim(claimsResponse.getClaim(), "urn:be:e-contract:iam:claims:self-claimed:software-key",
				"example-software-key"));
	}

	@Test
	public void testExampleWebServiceWithIdentityClaims() throws Exception {
		ExampleService exampleService = new ExampleService();
		ExampleServicePortType port = exampleService.getExampleServicePort();

		BeIDCards beIDCards = new BeIDCards();
		BeIDCard beIDCard = beIDCards.getOneBeIDCard();
		byte[] identity = beIDCard.readFile(FileType.Identity);
		byte[] identitySignature = beIDCard.readFile(FileType.IdentitySignature);
		byte[] nrCert = beIDCard.readFile(FileType.RRNCertificate);

		SecurityDecorator securityDecorator = new SecurityDecorator();
		securityDecorator.setOfficeKey("example-office-key");
		securityDecorator.setSoftwareKey("example-software-key");
		securityDecorator.setIdentity(identity);
		securityDecorator.setIdentitySignature(identitySignature);
		securityDecorator.setNationalRegistrationCertificate(nrCert);
		securityDecorator.decorate((BindingProvider) port, "https://www.e-contract.be/iam/example");

		// invoke the web service
		GetIdentityClaimsRequest getIdentityClaimsRequest = new GetIdentityClaimsRequest();
		ClaimsResponseType claimsResponse = port.getIdentityClaims(getIdentityClaimsRequest);
		LOGGER.debug("subject: {}", claimsResponse.getSubject());
		for (ClaimType claim : claimsResponse.getClaim()) {
			LOGGER.debug("claim {} = {}", claim.getName(), claim.getValue());
		}
		assertTrue(hasClaim(claimsResponse.getClaim(), "urn:be:e-contract:iam:claims:self-claimed:office-key",
				"example-office-key"));
		assertTrue(hasClaim(claimsResponse.getClaim(), "urn:be:e-contract:iam:claims:self-claimed:software-key",
				"example-software-key"));
		assertTrue(
				hasClaim(claimsResponse.getClaim(), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"));
	}

	@Test
	public void testExampleWebServiceWithAddressClaims() throws Exception {
		ExampleService exampleService = new ExampleService();
		ExampleServicePortType port = exampleService.getExampleServicePort();

		BeIDCards beIDCards = new BeIDCards();
		BeIDCard beIDCard = beIDCards.getOneBeIDCard();
		byte[] identity = beIDCard.readFile(FileType.Identity);
		byte[] identitySignature = beIDCard.readFile(FileType.IdentitySignature);
		byte[] nrCert = beIDCard.readFile(FileType.RRNCertificate);
		byte[] address = beIDCard.readFile(FileType.Address);
		byte[] addressSignature = beIDCard.readFile(FileType.AddressSignature);

		SecurityDecorator securityDecorator = new SecurityDecorator();
		securityDecorator.setOfficeKey("example-office-key");
		securityDecorator.setSoftwareKey("example-software-key");
		securityDecorator.setIdentity(identity);
		securityDecorator.setIdentitySignature(identitySignature);
		securityDecorator.setNationalRegistrationCertificate(nrCert);
		securityDecorator.setAddress(address);
		securityDecorator.setAddressSignature(addressSignature);
		securityDecorator.decorate((BindingProvider) port, "https://www.e-contract.be/iam/example");

		// invoke the web service
		GetAddressClaimsRequest getAddressClaimsRequest = new GetAddressClaimsRequest();
		ClaimsResponseType claimsResponse = port.getAddressClaims(getAddressClaimsRequest);
		LOGGER.debug("subject: {}", claimsResponse.getSubject());
		for (ClaimType claim : claimsResponse.getClaim()) {
			LOGGER.debug("claim {} = {}", claim.getName(), claim.getValue());
		}
		assertTrue(hasClaim(claimsResponse.getClaim(), "urn:be:e-contract:iam:claims:self-claimed:office-key",
				"example-office-key"));
		assertTrue(hasClaim(claimsResponse.getClaim(), "urn:be:e-contract:iam:claims:self-claimed:software-key",
				"example-software-key"));
		assertTrue(hasClaim(claimsResponse.getClaim(),
				"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/streetaddress"));
	}

	private boolean hasClaim(List<ClaimType> claims, String name, String value) {
		for (ClaimType claim : claims) {
			if (claim.getName().equals(name)) {
				if (claim.getValue().equals(value)) {
					return true;
				}
			}
		}
		return false;
	}

	private boolean hasClaim(List<ClaimType> claims, String name) {
		for (ClaimType claim : claims) {
			if (claim.getName().equals(name)) {
				return true;
			}
		}
		return false;
	}

	@Test
	public void testSelfSignedCertificateFails() throws Exception {
		ExampleService exampleService = new ExampleService();
		ExampleServicePortType port = exampleService.getExampleServicePort();

		// set the web service address on the client stub
		BindingProvider bindingProvider = (BindingProvider) port;
		Map<String, Object> requestContext = bindingProvider.getRequestContext();
		requestContext.put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, "https://www.e-contract.be/iam/example");

		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();
		X509Certificate certificate = getCertificate(privateKey, publicKey);
		List<X509Certificate> certificates = new LinkedList<>();
		certificates.add(certificate);

		requestContext.put(SecurityConstants.STS_CLIENT_SOAP12_BINDING, "true");
		requestContext.put(SecurityConstants.SIGNATURE_CRYPTO, new ClientCrypto(privateKey, certificates));
		requestContext.put(SecurityConstants.STS_TOKEN_USE_CERT_FOR_KEYINFO, "true");
		requestContext.put(SecurityConstants.SIGNATURE_USERNAME, "username");
		requestContext.put(SecurityConstants.CALLBACK_HANDLER, new ExampleSecurityPolicyCallbackHandler());
		requestContext.put(SecurityConstants.PREFER_WSMEX_OVER_STS_CLIENT_CONFIG, "true");

		// invoke the web service
		try {
			port.echo("hello world");
			fail();
		} catch (SOAPFaultException e) {
			// expected
			assertTrue(e.getMessage().contains("security token"));
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

	@Test
	public void testExampleWebServiceHolderOfKey() throws Exception {
		ExampleService exampleService = new ExampleService();
		ExampleServicePortType port = exampleService.getExampleServicePort();

		BindingProvider bindingProvider = (BindingProvider) port;
		Binding binding = bindingProvider.getBinding();
		List<Handler> handlerChain = binding.getHandlerChain();
		handlerChain.add(new LoggingSOAPHandler());
		binding.setHandlerChain(handlerChain);

		SecurityDecorator securityDecorator = new SecurityDecorator();
		securityDecorator.decorate((BindingProvider) port, "https://www.e-contract.be/iam/example");

		// invoke the web service
		port.holderOfKeyEcho("hello world");
	}

	@Test
	public void testUsernamePasswordCXFSTS() throws Exception {
		SpringBusFactory bf = new SpringBusFactory();
		Bus bus = bf.createBus("cxf-https-trust-all.xml");
		STSClient stsClient = new STSClient(bus);
		stsClient.setSoap12();
		String stsUsernameUrl = "https://localhost.localdomain/iam/users-sts/";
		stsClient.setWsdlLocation(stsUsernameUrl + "?wsdl");
		stsClient.setLocation(stsUsernameUrl);
		stsClient.setServiceName("{http://docs.oasis-open.org/ws-sx/ws-trust/200512}SecurityTokenService");
		stsClient.setEndpointName("{http://docs.oasis-open.org/ws-sx/ws-trust/200512}SecurityTokenServicePort");
		stsClient.setKeyType("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer");
		stsClient.setTokenType("urn:oasis:names:tc:SAML:2.0:assertion");
		stsClient.setAllowRenewing(false);

		Map<String, Object> properties = stsClient.getProperties();
		properties.put(SecurityConstants.USERNAME, "username");
		properties.put(SecurityConstants.PASSWORD, "password");
		stsClient.setProperties(properties);

		LOGGER.debug("STS location: {}", stsClient.getLocation());
		SecurityToken securityToken = stsClient.requestSecurityToken("https://demo.app.applies.to");
		Principal principal = securityToken.getPrincipal();
		LOGGER.debug("principal: {}", principal);
		LOGGER.debug("token type: {}", securityToken.getTokenType());
		assertEquals("urn:oasis:names:tc:SAML:2.0:assertion", securityToken.getTokenType());
		LOGGER.debug("security token expires: {}", securityToken.getExpires());

		bus.shutdown(true);
	}

	@Test
	public void testCreateKeyStore() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();
		Certificate[] certs = new Certificate[1];
		certs[0] = getCertificate("CN=TestApp", privateKey, publicKey);

		KeyStore outStore = KeyStore.getInstance("PKCS12");
		outStore.load(null, "secret".toCharArray());
		outStore.setKeyEntry("mykey", privateKey, "secret".toCharArray(), certs);
		File keyStoreFile = File.createTempFile("keystore-", ".p12");
		OutputStream outputStream = new FileOutputStream(keyStoreFile);
		outStore.store(outputStream, "secret".toCharArray());
		outputStream.flush();
		outputStream.close();
		LOGGER.debug("keystore file: {}", keyStoreFile.getAbsolutePath());
		File certFile = File.createTempFile("cert-", ".der");
		FileUtils.writeByteArrayToFile(certFile, certs[0].getEncoded());
		LOGGER.debug("cert file: {}", certFile.getAbsolutePath());
	}

	@Test
	public void testOnBehalfOfActAs() throws Exception {
		// setup
		FileInputStream idpKeyStoreFile = new FileInputStream("/home/fcorneli/test-idp.p12");
		KeyStore idpKeyStore = KeyStore.getInstance("PKCS12");
		idpKeyStore.load(idpKeyStoreFile, "secret".toCharArray());
		String idpAlias = idpKeyStore.aliases().nextElement();
		PrivateKeyEntry idpPrivateKeyEntry = (PrivateKeyEntry) idpKeyStore.getEntry(idpAlias,
				new KeyStore.PasswordProtection("secret".toCharArray()));
		PrivateKey idpPrivateKey = idpPrivateKeyEntry.getPrivateKey();
		X509Certificate idpCertificate = (X509Certificate) idpPrivateKeyEntry.getCertificate();
		Element onBehalfOfToken = generateToken(idpPrivateKey, idpCertificate);
		LOGGER.debug("OnBehalfOf SAML token: {}", toFormattedString(onBehalfOfToken));

		Element actAsToken = generateActAsToken();
		LOGGER.debug("ActAs SAML token: {}", toFormattedString(actAsToken));

		FileInputStream appKeyStoreFile = new FileInputStream("/home/fcorneli/test-app.p12");
		KeyStore appKeyStore = KeyStore.getInstance("PKCS12");
		appKeyStore.load(appKeyStoreFile, "secret".toCharArray());
		String appAlias = appKeyStore.aliases().nextElement();
		PrivateKeyEntry appPrivateKeyEntry = (PrivateKeyEntry) appKeyStore.getEntry(appAlias,
				new KeyStore.PasswordProtection("secret".toCharArray()));
		PrivateKey appPrivateKey = appPrivateKeyEntry.getPrivateKey();
		X509Certificate appCertificate = (X509Certificate) appPrivateKeyEntry.getCertificate();

		SpringBusFactory bf = new SpringBusFactory();
		Bus bus = bf.createBus("cxf-https-trust-all.xml");
		STSClient stsClient = new STSClient(bus);
		stsClient.setSoap12();
		stsClient.setWsdlLocation(ONBEHALFOF_STS_LOCATION + "?wsdl");
		stsClient.setLocation(ONBEHALFOF_STS_LOCATION);
		stsClient.setServiceName("{http://docs.oasis-open.org/ws-sx/ws-trust/200512}SecurityTokenService");
		stsClient.setEndpointName("{http://docs.oasis-open.org/ws-sx/ws-trust/200512}SecurityTokenServicePort");
		stsClient.setTokenType("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0");
		stsClient.setKeyType("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer");
		Map<String, Object> properties = stsClient.getProperties();
		properties.put(SecurityConstants.SIGNATURE_USERNAME, "username");
		properties.put(SecurityConstants.CALLBACK_HANDLER, new ExampleSecurityPolicyCallbackHandler());
		properties.put(SecurityConstants.SIGNATURE_CRYPTO, new ClientCrypto(appPrivateKey, appCertificate));
		stsClient.setProperties(properties);
		stsClient.setOnBehalfOf(onBehalfOfToken);
		stsClient.setClaims(createClaims());
		stsClient.setActAs(actAsToken);
		stsClient.setEnableLifetime(true);
		stsClient.setTtl(60 * 60 * 5);

		// operate
		SecurityToken securityToken = stsClient.requestSecurityToken("http://active.saml.token.target");

		// verify
		Element tokenElement = securityToken.getToken();
		LOGGER.debug("STS SAML token: {}", toFormattedString(tokenElement));
		AssertionWrapper assertionWrapper = new AssertionWrapper(tokenElement);
		Assertion assertion = assertionWrapper.getSaml2();
		assertTrue(assertion.isSigned());

		BasicX509Credential validatingCredential = new BasicX509Credential();
		validatingCredential.setEntityCertificate(TestOnBehalfOfService.getSAMLSignerCertificate());
		SignatureValidator signatureValidator = new SignatureValidator(validatingCredential);
		//signatureValidator.validate(assertion.getSignature());

		assertEquals("subject", assertion.getSubject().getNameID().getValue());
		List<Attribute> attributes = assertion.getAttributeStatements().get(0).getAttributes();
		assertAttribute(attributes, "urn:be:e-contract:iam:claims:self-claimed:office-key", "office-key-value");
		assertAttribute(attributes, "urn:be:e-contract:iam:claims:self-claimed:software-key", "software-key-value");
	}

	private Element generateActAsToken() throws Exception {
		DefaultBootstrap.bootstrap();
		XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
		SAMLObjectBuilder<Assertion> assertionBuilder = (SAMLObjectBuilder<Assertion>) builderFactory
				.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
		Assertion assertion = assertionBuilder.buildObject();
		assertion.setID("saml-id");

		SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory
				.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
		Issuer issuer = issuerBuilder.buildObject();
		issuer.setValue("act-as-issuer");
		assertion.setIssuer(issuer);

		DateTime issueInstance = new DateTime();
		assertion.setIssueInstant(issueInstance);

		SAMLObjectBuilder<AttributeStatement> attributeStatementBuilder = (SAMLObjectBuilder<AttributeStatement>) builderFactory
				.getBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME);
		AttributeStatement attributeStatement = attributeStatementBuilder.buildObject();
		assertion.getAttributeStatements().add(attributeStatement);
		SAMLObjectBuilder<Attribute> attributeBuilder = (SAMLObjectBuilder<Attribute>) builderFactory
				.getBuilder(Attribute.DEFAULT_ELEMENT_NAME);

		{
			Attribute attribute = attributeBuilder.buildObject();
			attributeStatement.getAttributes().add(attribute);
			attribute.setName("urn:be:e-contract:iam:claims:self-claimed:office-key");
			XMLObjectBuilder<XSString> attributeValueBuilder = (XMLObjectBuilder<XSString>) builderFactory
					.getBuilder(XSString.TYPE_NAME);
			XSString attributeValue = (XSString) attributeValueBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
					XSString.TYPE_NAME);
			attributeValue.setValue("office-key-value");
			attribute.getAttributeValues().add(attributeValue);
		}

		{
			Attribute attribute = attributeBuilder.buildObject();
			attributeStatement.getAttributes().add(attribute);
			attribute.setName("urn:be:e-contract:iam:claims:self-claimed:software-key");
			XMLObjectBuilder<XSString> attributeValueBuilder = (XMLObjectBuilder<XSString>) builderFactory
					.getBuilder(XSString.TYPE_NAME);
			XSString attributeValue = (XSString) attributeValueBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
					XSString.TYPE_NAME);
			attributeValue.setValue("software-key-value");
			attribute.getAttributeValues().add(attributeValue);
		}

		MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
		Marshaller marshaller = marshallerFactory.getMarshaller(assertion);
		Element token = marshaller.marshall(assertion);

		return token;
	}

	private Element createClaims() {
		Document doc = DOMUtils.createDocument();
		Element claimsElement = doc.createElementNS("http://docs.oasis-open.org/ws-sx/ws-trust/200512", "Claims");
		claimsElement.setAttributeNS(null, "Dialect", "http://schemas.xmlsoap.org/ws/2005/05/identity");

		Element officeKeyClaimType = doc.createElementNS("http://schemas.xmlsoap.org/ws/2005/05/identity", "ClaimType");
		officeKeyClaimType.setAttributeNS(null, "Uri", "urn:be:e-contract:iam:claims:self-claimed:office-key");
		claimsElement.appendChild(officeKeyClaimType);

		Element softwareKeyClaimType = doc.createElementNS("http://schemas.xmlsoap.org/ws/2005/05/identity",
				"ClaimType");
		softwareKeyClaimType.setAttributeNS(null, "Uri", "urn:be:e-contract:iam:claims:self-claimed:software-key");
		claimsElement.appendChild(softwareKeyClaimType);

		return claimsElement;
	}

	private void assertAttribute(List<Attribute> attributes, String attributeName, String extectedAttributeValue) {
		for (Attribute attribute : attributes) {
			if (!attributeName.equals(attribute.getName())) {
				continue;
			}
			List<XMLObject> attributeValues = attribute.getAttributeValues();
			for (XMLObject attributeValue : attributeValues) {
				LOGGER.debug("attribute value class: {}", attributeValue.getClass().getName());
				if (attributeValue instanceof XSString) {
					XSString stringAttributeValue = (XSString) attributeValue;
					if (extectedAttributeValue.equals(stringAttributeValue.getValue())) {
						return;
					}
				}
			}
		}
		throw new RuntimeException("attribute not found");
	}

	private X509Certificate getCertificate(String name, PrivateKey privateKey, PublicKey publicKey) throws Exception {
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

	private Element generateToken(PrivateKey privateKey, X509Certificate certificate) throws Exception {
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

		SAMLObjectBuilder<AttributeStatement> attributeStatementBuilder = (SAMLObjectBuilder<AttributeStatement>) builderFactory
				.getBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME);
		AttributeStatement attributeStatement = attributeStatementBuilder.buildObject();
		assertion.getAttributeStatements().add(attributeStatement);
		SAMLObjectBuilder<Attribute> attributeBuilder = (SAMLObjectBuilder<Attribute>) builderFactory
				.getBuilder(Attribute.DEFAULT_ELEMENT_NAME);
		Attribute attribute = attributeBuilder.buildObject();
		attributeStatement.getAttributes().add(attribute);
		attribute.setName("test-attribute");
		XMLObjectBuilder<XSString> attributeValueBuilder = (XMLObjectBuilder<XSString>) builderFactory
				.getBuilder(XSString.TYPE_NAME);
		XSString attributeValue = (XSString) attributeValueBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
				XSString.TYPE_NAME);
		attributeValue.setValue("attribute value");
		attribute.getAttributeValues().add(attributeValue);

		SignatureBuilder signatureBuilder = new SignatureBuilder();
		Signature signature = signatureBuilder.buildObject();
		BasicX509Credential credential = new BasicX509Credential();
		credential.setPrivateKey(privateKey);
		credential.setEntityCertificate(certificate);
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
