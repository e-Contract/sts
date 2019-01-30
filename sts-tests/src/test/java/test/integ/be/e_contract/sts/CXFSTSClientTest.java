/*
 * eID Security Token Service Project.
 * Copyright (C) 2014-2015 e-Contract.be BVBA.
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
import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.namespace.QName;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.soap.SOAPFaultException;

import org.apache.commons.io.FileUtils;
import org.apache.cxf.Bus;
import org.apache.cxf.BusFactory;
import org.apache.cxf.bus.spring.SpringBusFactory;
import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.databinding.source.SourceDataBinding;
import org.apache.cxf.endpoint.Client;
import org.apache.cxf.endpoint.Endpoint;
import org.apache.cxf.endpoint.EndpointImpl;
import org.apache.cxf.service.Service;
import org.apache.cxf.service.model.EndpointInfo;
import org.apache.cxf.transport.http.HTTPConduit;
import org.apache.cxf.ws.security.SecurityConstants;
import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.apache.cxf.ws.security.trust.STSClient;
import org.apache.cxf.wsdl11.WSDLServiceFactory;
import org.apache.ws.security.WSPasswordCallback;
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
import org.w3c.dom.Element;

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

public class CXFSTSClientTest {

	private static final Logger LOGGER = LoggerFactory.getLogger(CXFSTSClientTest.class);

	@Before
	public void setUp() throws Exception {
		TrustManager trustManager = new MyTrustManager();
		TrustManager[] sslTrustManagers = new TrustManager[] { trustManager };
		SSLContext ssl_ctx = SSLContext.getInstance("TLS");
		ssl_ctx.init(null, sslTrustManagers, new SecureRandom());
		SSLSocketFactory sslSocketFactory = ssl_ctx.getSocketFactory();
		HttpsURLConnection.setDefaultSSLSocketFactory(sslSocketFactory);

		HostnameVerifier hostnameVerifier = new MyHostnameVerifier();
		HttpsURLConnection.setDefaultHostnameVerifier(hostnameVerifier);

		Security.addProvider(new BeIDProvider());
	}

	public static class MyHostnameVerifier implements HostnameVerifier {

		@Override
		public boolean verify(String arg0, SSLSession arg1) {
			return true;
		}
	}

	public static class MyTrustManager implements X509TrustManager {

		private static final Logger LOGGER = LoggerFactory.getLogger(MyTrustManager.class);

		@Override
		public void checkClientTrusted(X509Certificate[] certs, String arg1) throws CertificateException {
			LOGGER.debug("check client trusted: {}", certs[0]);
		}

		@Override
		public void checkServerTrusted(X509Certificate[] certs, String arg1) throws CertificateException {
			LOGGER.debug("server cert: {}", certs[0].toString());
		}

		@Override
		public X509Certificate[] getAcceptedIssuers() {
			LOGGER.debug("getAcceptedIssuers");
			return new X509Certificate[0];
		}
	}

	@Test
	public void testExampleWebService() throws Exception {
		SpringBusFactory bf = new SpringBusFactory();
		Bus bus = bf.createBus("cxf-https-trust-all.xml");
		BusFactory.setDefaultBus(bus);
		// get the JAX-WS client
		URL wsdlLocation = CXFSTSClientTest.class.getResource("/example-localhost-sts.wsdl");
		ExampleService exampleService = new ExampleService(wsdlLocation,
				new QName("urn:be:e-contract:sts:example", "ExampleService"));
		ExampleServicePortType port = exampleService.getExampleServicePort();

		// set the web service address on the client stub
		BindingProvider bindingProvider = (BindingProvider) port;
		Map<String, Object> requestContext = bindingProvider.getRequestContext();
		final String WS_LOCATION = "https://localhost/iam/example";
		// final String WS_LOCATION = "https://www.e-contract.be/iam/example";
		requestContext.put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, WS_LOCATION);

		requestContext.put(SecurityConstants.STS_CLIENT_SOAP12_BINDING, "true");
		requestContext.put(SecurityConstants.SIGNATURE_CRYPTO, new BeIDCrypto());
		requestContext.put(SecurityConstants.STS_TOKEN_USE_CERT_FOR_KEYINFO, "true");
		requestContext.put(SecurityConstants.SIGNATURE_USERNAME, "username");
		requestContext.put(SecurityConstants.CALLBACK_HANDLER, new ExampleSecurityPolicyCallbackHandler());
		requestContext.put(SecurityConstants.PREFER_WSMEX_OVER_STS_CLIENT_CONFIG, "true");

		// invoke the web service
		String result = port.echo("hello world");
		LOGGER.debug("result: " + result);

		bus.shutdown(true);
	}

	@Test
	public void testExampleWebServiceWithClaims() throws Exception {
		SpringBusFactory bf = new SpringBusFactory();
		Bus bus = bf.createBus("cxf-https-trust-all.xml");
		BusFactory.setDefaultBus(bus);
		// get the JAX-WS client
		URL wsdlLocation = CXFSTSClientTest.class.getResource("/example-localhost-sts.wsdl");
		ExampleService exampleService = new ExampleService(wsdlLocation,
				new QName("urn:be:e-contract:sts:example", "ExampleService"));
		ExampleServicePortType port = exampleService.getExampleServicePort();

		SecurityDecorator securityDecorator = new SecurityDecorator();
		securityDecorator.setOfficeKey("example-office-key");
		securityDecorator.setSoftwareKey("example-software-key");
		securityDecorator.decorate((BindingProvider) port, "https://localhost/iam/example");

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

		bus.shutdown(true);
	}

	@Test
	public void testExampleWebServiceHolderOfKey() throws Exception {
		SpringBusFactory bf = new SpringBusFactory();
		Bus bus = bf.createBus("cxf-https-trust-all.xml");
		BusFactory.setDefaultBus(bus);
		// get the JAX-WS client
		URL wsdlLocation = CXFSTSClientTest.class.getResource("/example-localhost-sts.wsdl");
		ExampleService exampleService = new ExampleService(wsdlLocation,
				new QName("urn:be:e-contract:sts:example", "ExampleService"));
		ExampleServicePortType port = exampleService.getExampleServicePort();

		SecurityDecorator securityDecorator = new SecurityDecorator();
		securityDecorator.decorate((BindingProvider) port, "https://localhost/iam/example");

		// invoke the web service
		port.holderOfKeyEcho("hello world");

		bus.shutdown(true);
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
	public void testExampleWebServiceWithClaimsAndActAsToken() throws Exception {
		SpringBusFactory bf = new SpringBusFactory();
		Bus bus = bf.createBus("cxf-https-trust-all.xml");
		BusFactory.setDefaultBus(bus);
		// get the JAX-WS client
		URL wsdlLocation = CXFSTSClientTest.class.getResource("/example-localhost-sts.wsdl");
		ExampleService exampleService = new ExampleService(wsdlLocation,
				new QName("urn:be:e-contract:sts:example", "ExampleService"));
		ExampleServicePortType port = exampleService.getExampleServicePort();

		SecurityDecorator securityDecorator = new SecurityDecorator();
		securityDecorator.setOfficeKey("example-office-key");
		securityDecorator.setSoftwareKey("example-software-key");
		securityDecorator.decorate((BindingProvider) port, "https://localhost/iam/example");

		// invoke the web service
		GetSelfClaimsRequest getSelfClaimsRequest = new GetSelfClaimsRequest();
		ClaimsResponseType claimsResponse = port.getSelfClaims(getSelfClaimsRequest);
		LOGGER.debug("subject: {}", claimsResponse.getSubject());
		for (ClaimType claim : claimsResponse.getClaim()) {
			LOGGER.debug("claim {} = {}", claim.getName(), claim.getValue());
		}

		bus.shutdown(true);
	}

	@Test
	public void testExampleWebServiceWithIdentityClaims() throws Exception {
		SpringBusFactory bf = new SpringBusFactory();
		Bus bus = bf.createBus("cxf-https-trust-all.xml");
		BusFactory.setDefaultBus(bus);
		// get the JAX-WS client
		URL wsdlLocation = CXFSTSClientTest.class.getResource("/example-localhost-sts.wsdl");
		ExampleService exampleService = new ExampleService(wsdlLocation,
				new QName("urn:be:e-contract:sts:example", "ExampleService"));
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
		securityDecorator.decorate((BindingProvider) port, "https://localhost/iam/example");

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

		bus.shutdown(true);
	}

	@Test
	public void testExampleWebServiceWithAddressClaims() throws Exception {
		SpringBusFactory bf = new SpringBusFactory();
		Bus bus = bf.createBus("cxf-https-trust-all.xml");
		BusFactory.setDefaultBus(bus);
		// get the JAX-WS client
		URL wsdlLocation = CXFSTSClientTest.class.getResource("/example-localhost-sts.wsdl");
		ExampleService exampleService = new ExampleService(wsdlLocation,
				new QName("urn:be:e-contract:sts:example", "ExampleService"));
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
		securityDecorator.decorate((BindingProvider) port, "https://localhost/iam/example");

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

		bus.shutdown(true);
	}

	@Test
	public void testSelfSignedCertificateFails() throws Exception {
		SpringBusFactory bf = new SpringBusFactory();
		Bus bus = bf.createBus("cxf-https-trust-all.xml");
		BusFactory.setDefaultBus(bus);
		// get the JAX-WS client
		URL wsdlLocation = CXFSTSClientTest.class.getResource("/example-localhost-sts.wsdl");
		ExampleService exampleService = new ExampleService(wsdlLocation,
				new QName("urn:be:e-contract:sts:example", "ExampleService"));
		ExampleServicePortType port = exampleService.getExampleServicePort();

		// set the web service address on the client stub
		BindingProvider bindingProvider = (BindingProvider) port;
		Map<String, Object> requestContext = bindingProvider.getRequestContext();
		requestContext.put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, "https://localhost/iam/example");

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

		bus.shutdown(true);
	}

	@Test
	public void testCXFSTS() throws Exception {
		// SpringBusFactory bf = new SpringBusFactory();
		// Bus bus = bf.createBus();
		Bus bus = BusFactory.getDefaultBus();
		STSClient stsClient = new STSClient(bus);
		stsClient.setSoap12();
		stsClient.setWsdlLocation("https://localhost/iam/sts?wsdl");
		stsClient.setLocation("https://localhost/iam/sts");
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

		Client client = stsClient.getClient();
		HTTPConduit httpConduit = (HTTPConduit) client.getConduit();
		TLSClientParameters tlsParams = new TLSClientParameters();
		tlsParams.setSecureSocketProtocol("TLSv1");
		tlsParams.setDisableCNCheck(true);
		tlsParams.setTrustManagers(new TrustManager[] { new MyTrustManager() });
		httpConduit.setTlsClientParameters(tlsParams);

		LOGGER.debug("STS location: {}", stsClient.getLocation());
		SecurityToken securityToken = stsClient.requestSecurityToken("https://demo.app.applies.to");
		Principal principal = securityToken.getPrincipal();
		LOGGER.debug("principal: {}", principal);
		LOGGER.debug("token type: {}", securityToken.getTokenType());
		assertEquals("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0",
				securityToken.getTokenType());
		LOGGER.debug("security token expires: {}", securityToken.getExpires());

		LOGGER.debug("---------------------------------------------------------------");
		stsClient.setEnableAppliesTo(true);
		stsClient.setTokenType("http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/Status");
		List<SecurityToken> result = stsClient.validateSecurityToken(securityToken);
		assertEquals(1, result.size());
		SecurityToken resultSecurityToken = result.get(0);
		LOGGER.debug("token type: {}", resultSecurityToken.getTokenType());
		assertEquals("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0",
				resultSecurityToken.getTokenType());
	}

	@Test
	public void testBearer() throws Exception {
		SpringBusFactory bf = new SpringBusFactory();
		Bus bus = bf.createBus("cxf-https-trust-all.xml");
		BusFactory.setDefaultBus(bus);
		STSClient stsClient = new STSClient(bus);
		stsClient.setSoap12();
		stsClient.setWsdlLocation("https://localhost/iam/sts?wsdl");
		stsClient.setLocation("https://localhost/iam/sts");
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

		Client client = stsClient.getClient();
		HTTPConduit httpConduit = (HTTPConduit) client.getConduit();
		TLSClientParameters tlsParams = new TLSClientParameters();
		tlsParams.setSecureSocketProtocol("TLSv1");
		tlsParams.setDisableCNCheck(true);
		tlsParams.setTrustManagers(new TrustManager[] { new MyTrustManager() });
		httpConduit.setTlsClientParameters(tlsParams);

		LOGGER.debug("STS location: {}", stsClient.getLocation());
		SecurityToken securityToken = stsClient.requestSecurityToken("https://localhost/iam/example");
		Element assertionElement = securityToken.getToken();

		URL wsdlLocation = CXFSTSClientTest.class.getResource("/example-localhost-sts.wsdl");
		ExampleService exampleService = new ExampleService(wsdlLocation,
				new QName("urn:be:e-contract:sts:example", "ExampleService"));
		ExampleServicePortType port = exampleService.getExampleServicePort();

		SecurityDecorator securityDecorator = new SecurityDecorator();
		securityDecorator.decorate((BindingProvider) port, assertionElement, "https://localhost/iam/example");

		BearerRequest bearerRequest = new BearerRequest();
		ClaimsResponseType response = port.bearer(bearerRequest);
		LOGGER.debug("subject: {}", response.getSubject());
		for (ClaimType claim : response.getClaim()) {
			LOGGER.debug("claim {} = {}", claim.getName(), claim.getValue());
		}
	}

	@Test
	public void testCXFSTSWithClaimsAndActAsAssertion() throws Exception {
		// SpringBusFactory bf = new SpringBusFactory();
		// Bus bus = bf.createBus();
		Bus bus = BusFactory.getDefaultBus();
		STSClient stsClient = new STSClient(bus);
		stsClient.setSoap12();
		stsClient.setWsdlLocation("https://localhost/iam/sts?wsdl");
		stsClient.setLocation("https://localhost/iam/sts");
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

		Client client = stsClient.getClient();
		HTTPConduit httpConduit = (HTTPConduit) client.getConduit();
		TLSClientParameters tlsParams = new TLSClientParameters();
		tlsParams.setSecureSocketProtocol("TLSv1");
		tlsParams.setDisableCNCheck(true);
		tlsParams.setTrustManagers(new TrustManager[] { new MyTrustManager() });
		httpConduit.setTlsClientParameters(tlsParams);

		LOGGER.debug("STS location: {}", stsClient.getLocation());
		SecurityToken securityToken = stsClient.requestSecurityToken("https://localhost/iam/example");
		Principal principal = securityToken.getPrincipal();
		LOGGER.debug("principal: {}", principal);
		LOGGER.debug("token type: {}", securityToken.getTokenType());
		assertEquals("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0",
				securityToken.getTokenType());
		LOGGER.debug("security token expires: {}", securityToken.getExpires());

		LOGGER.debug("---------------------------------------------------------------");
		stsClient.setEnableAppliesTo(true);
		stsClient.setTokenType("http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/Status");
		List<SecurityToken> result = stsClient.validateSecurityToken(securityToken);
		assertEquals(1, result.size());
		SecurityToken resultSecurityToken = result.get(0);
		LOGGER.debug("token type: {}", resultSecurityToken.getTokenType());
		assertEquals("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0",
				resultSecurityToken.getTokenType());
	}

	@Test
	public void testBeIDAuthnCertToFile() throws Exception {
		KeyStore keyStore = KeyStore.getInstance("BeID");
		keyStore.load(null);
		Certificate certificate = keyStore.getCertificate("Authentication");
		File tmpFile = File.createTempFile("eid-authn-", ".der");
		FileUtils.writeByteArrayToFile(tmpFile, certificate.getEncoded());
		LOGGER.debug("eID authn cert file: {}", tmpFile.getAbsolutePath());
	}

	@Test
	public void testCXFWSDL() throws Exception {
		Bus bus = BusFactory.getDefaultBus();
		// String wsdlLocation = CXFSTSClientTest.class
		// .getResource("/ws-trust-1.3.wsdl").toURI().toURL().toString();
		String wsdlLocation = "https://localhost/iam/sts?wsdl";
		QName serviceName = new QName("http://docs.oasis-open.org/ws-sx/ws-trust/200512", "SecurityTokenService");
		WSDLServiceFactory factory = new WSDLServiceFactory(bus, wsdlLocation, serviceName);
		SourceDataBinding dataBinding = new SourceDataBinding();
		factory.setDataBinding(dataBinding);
		Service service = factory.create();
		service.setDataBinding(dataBinding);
		QName endpointName = new QName("", "");
		LOGGER.debug("number of endpoints: {}", service.getEndpoints().size());
		for (QName endpointQName : service.getEndpoints().keySet()) {
			LOGGER.debug("endpoint name: {}", endpointQName.toString());
		}
		EndpointInfo ei = service.getEndpointInfo(endpointName);
		Endpoint endpoint = new EndpointImpl(bus, service, ei);
	}

	@Test
	public void testCXFExampleSecurityPolicy() throws Exception {
		Bus bus = BusFactory.getDefaultBus();
		String wsdlLocation = CXFSTSClientTest.class.getResource("/example-security-policy.wsdl").toURI().toURL()
				.toString();
		QName serviceName = new QName("urn:be:e-contract:sts:example", "ExampleService");
		WSDLServiceFactory factory = new WSDLServiceFactory(bus, wsdlLocation, serviceName);
		SourceDataBinding dataBinding = new SourceDataBinding();
		factory.setDataBinding(dataBinding);
		Service service = factory.create();
		service.setDataBinding(dataBinding);
		QName endpointName = new QName("", "");
		LOGGER.debug("number of endpoints: {}", service.getEndpoints().size());
		for (QName endpointQName : service.getEndpoints().keySet()) {
			LOGGER.debug("endpoint name: {}", endpointQName.toString());
		}
		EndpointInfo ei = service.getEndpointInfo(endpointName);
		Endpoint endpoint = new EndpointImpl(bus, service, ei);
	}

	@Test
	public void testCXFWSDLAGIV() throws Exception {
		Bus bus = BusFactory.getDefaultBus();
		// String wsdlLocation = CXFSTSClientTest.class
		// .getResource("/ws-trust-1.3.wsdl").toURI().toURL().toString();
		String wsdlLocation = "https://auth.beta.agiv.be/ipsts/Services/DaliSecurityTokenServiceConfiguration.svc?wsdl";
		QName serviceName = new QName("http://docs.oasis-open.org/ws-sx/ws-trust/200512", "SecurityTokenService");
		WSDLServiceFactory factory = new WSDLServiceFactory(bus, wsdlLocation, serviceName);
		SourceDataBinding dataBinding = new SourceDataBinding();
		factory.setDataBinding(dataBinding);
		Service service = factory.create();
		service.setDataBinding(dataBinding);
		QName endpointName = new QName("", "");
		LOGGER.debug("number of endpoints: {}", service.getEndpoints().size());
		for (QName endpointQName : service.getEndpoints().keySet()) {
			LOGGER.debug("endpoint name: {}", endpointQName.toString());
		}
		EndpointInfo ei = service.getEndpointInfo(endpointName);
		Endpoint endpoint = new EndpointImpl(bus, service, ei);
	}

	public class UTCallbackHandler implements CallbackHandler {

		@Override
		public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
			LOGGER.debug("callback handler invoked");
			for (Callback callback : callbacks) {
				LOGGER.debug("callback type: " + callback.getClass().getName());
				if (callback instanceof WSPasswordCallback) {
					WSPasswordCallback wsPasswordCallback = (WSPasswordCallback) callback;
					if (wsPasswordCallback.getIdentifier().equals("username")) {
						wsPasswordCallback.setPassword("password");
					}
				}
			}
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
}
