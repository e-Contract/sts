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

import be.e_contract.sts.client.cxf.SecurityDecorator;
import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.xml.ws.Binding;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.Endpoint;
import javax.xml.ws.handler.Handler;

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
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import test.integ.be.e_contract.sts.CXFSTSClientTest.MyHostnameVerifier;
import test.integ.be.e_contract.sts.CXFSTSClientTest.MyTrustManager;
import be.e_contract.sts.example.ExampleService;
import be.e_contract.sts.example.ExampleServicePortType;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class SecurityPolicyTest {

	private static final Logger LOGGER = LoggerFactory
			.getLogger(SecurityPolicyTest.class);

	private String url;

	private Endpoint endpoint;

	private String url2;

	private Endpoint endpoint2;

	private String url3;

	private Endpoint endpoint3;

	private String url4;

	private Endpoint endpoint4;

	private String url5;

	private Endpoint endpoint5;

	private String url6;

	private Endpoint endpoint6;

	private String url7;

	private Endpoint endpoint7;

	private String url8;

	private Endpoint endpoint8;

	private String stsUrl;

	private Endpoint stsEndpoint;

	private String sts2Url;

	private Endpoint sts2Endpoint;

	private String stsUsernameUrl;

	private Endpoint stsUsernameEndpoint;

	private Bus bus;

	@Before
	public void setUp() throws Exception {
		int sslFreePort = 8443;// getFreePort();

		System.setProperty("testutil.ports.Server",
				Integer.toString(sslFreePort));

		SpringBusFactory bf = new SpringBusFactory();
		this.bus = bf.createBus("jaxws-server.xml");
		BusFactory.setDefaultBus(this.bus);

		this.url2 = "https://localhost:" + sslFreePort + "/example/ws2";
		this.endpoint2 = Endpoint.publish(this.url2,
				new ExampleSecurityPolicyServicePortImpl2());

		this.url3 = "https://localhost:" + sslFreePort + "/example/ws3";
		this.endpoint3 = Endpoint.publish(this.url3,
				new ExampleSecurityPolicyServicePortImpl3());

		this.url4 = "https://localhost:" + sslFreePort + "/example/ws4";
		this.endpoint4 = Endpoint.publish(this.url4,
				new ExampleSecurityPolicyServicePortImpl4());

		this.url5 = "https://localhost:" + sslFreePort + "/example/ws5";
		this.endpoint5 = Endpoint.publish(this.url5,
				new ExampleSecurityPolicyServicePortImpl5());

		this.stsUrl = "https://localhost:" + sslFreePort + "/example/sts";
		this.stsEndpoint = Endpoint.publish(this.stsUrl,
				new ExampleSecurityTokenService());

		this.sts2Url = "https://localhost:" + sslFreePort + "/example/sts2";
		this.sts2Endpoint = Endpoint.publish(this.sts2Url,
				new ExampleSecurityTokenServiceProvider());

		this.stsUsernameUrl = "https://localhost:" + sslFreePort
				+ "/example/sts-username";
		this.stsUsernameEndpoint = Endpoint.publish(this.stsUsernameUrl,
				new UsernamePasswordSecurityTokenServiceProvider());

		int freePort = getFreePort();
		this.url = "http://localhost:" + freePort + "/example/ws";
		this.endpoint = Endpoint.publish(this.url,
				new ExampleSecurityPolicyServicePortImpl());

		this.url6 = "https://localhost:" + sslFreePort + "/example/ws6";
		this.endpoint6 = Endpoint.publish(this.url6,
				new ExampleSecurityPolicyServicePortImpl6());

		this.url7 = "https://localhost:" + sslFreePort + "/example/ws7";
		this.endpoint7 = Endpoint.publish(this.url7,
				new ExampleSecurityPolicyServicePortImpl7());

		this.url8 = "https://localhost:" + sslFreePort + "/example/ws8";
		this.endpoint8 = Endpoint.publish(this.url8,
				new ExampleSecurityPolicyServicePortImpl8());

		TrustManager trustManager = new MyTrustManager();
		TrustManager[] sslTrustManagers = new TrustManager[]{trustManager};
		SSLContext ssl_ctx = SSLContext.getInstance("TLS");
		ssl_ctx.init(null, sslTrustManagers, new SecureRandom());
		SSLSocketFactory sslSocketFactory = ssl_ctx.getSocketFactory();
		HttpsURLConnection.setDefaultSSLSocketFactory(sslSocketFactory);

		HostnameVerifier hostnameVerifier = new MyHostnameVerifier();
		HttpsURLConnection.setDefaultHostnameVerifier(hostnameVerifier);
	}

	@After
	public void tearDown() throws Exception {
		this.endpoint.stop();
		this.endpoint2.stop();
		this.endpoint3.stop();
		this.endpoint4.stop();
		this.endpoint5.stop();
		this.endpoint6.stop();
		this.endpoint7.stop();
		this.endpoint8.stop();
		this.stsEndpoint.stop();
		this.sts2Endpoint.stop();
		this.stsUsernameEndpoint.stop();
	}

	@Test
    public void testCXFSTSClient() throws Exception {
        SpringBusFactory bf = new SpringBusFactory();
        Bus bus = bf.createBus("cxf_https.xml");
        STSClient stsClient = new STSClient(bus);
        stsClient.setSoap12();
        stsClient.setWsdlLocation(this.sts2Url + "?wsdl");
        stsClient.setLocation(this.sts2Url);
        stsClient
                .setServiceName("{http://docs.oasis-open.org/ws-sx/ws-trust/200512}SecurityTokenService");
        stsClient
                .setEndpointName("{http://docs.oasis-open.org/ws-sx/ws-trust/200512}SecurityTokenServicePort");
        stsClient
                .setKeyType("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer");
        stsClient.setTokenType("urn:oasis:names:tc:SAML:2.0:assertion");
        stsClient.setAllowRenewing(false);

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        X509Certificate certificate = getCertificate(privateKey, publicKey);
        List<X509Certificate> certificates = new LinkedList<>();
        certificates.add(certificate);
        certificates.add(certificate);

        // Apache CXF specific configuration
        Map<String, Object> properties = stsClient.getProperties();
        properties.put(SecurityConstants.SIGNATURE_USERNAME, "username");
        properties.put(SecurityConstants.CALLBACK_HANDLER,
                new ExampleSecurityPolicyCallbackHandler());
        properties.put(SecurityConstants.SIGNATURE_CRYPTO, new ClientCrypto(
                privateKey, certificates));
        stsClient.setProperties(properties);

        stsClient.requestSecurityToken("https://demo.app.applies.to");
    }
	@Test
    public void testCXFSTSIssue() throws Exception {
        SpringBusFactory bf = new SpringBusFactory();
        Bus bus = bf.createBus("cxf_https.xml");
        STSClient stsClient = new STSClient(bus);
        stsClient.setSoap12();
        stsClient.setWsdlLocation(this.sts2Url + "?wsdl");
        stsClient.setLocation(this.sts2Url);
        stsClient
                .setServiceName("{http://docs.oasis-open.org/ws-sx/ws-trust/200512}SecurityTokenService");
        stsClient
                .setEndpointName("{http://docs.oasis-open.org/ws-sx/ws-trust/200512}SecurityTokenServicePort");
        stsClient
                .setKeyType("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer");
        stsClient
                .setTokenType("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0");
        stsClient.setAllowRenewing(false);

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        X509Certificate certificate = getCertificate(privateKey, publicKey);
        List<X509Certificate> certificates = new LinkedList<>();
        certificates.add(certificate);
		// certificates.add(certificate);

        // Apache CXF specific configuration
        Map<String, Object> properties = stsClient.getProperties();
        properties.put(SecurityConstants.SIGNATURE_USERNAME, "username");
        properties.put(SecurityConstants.CALLBACK_HANDLER,
                new ExampleSecurityPolicyCallbackHandler());
        properties.put(SecurityConstants.SIGNATURE_CRYPTO, new ClientCrypto(
                privateKey, certificates));
        stsClient.setProperties(properties);

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
	@Test
    public void testCXFSTS() throws Exception {
        SpringBusFactory bf = new SpringBusFactory();
        Bus bus = bf.createBus("cxf_https.xml");
        STSClient stsClient = new STSClient(bus);
        stsClient.setSoap12();
        stsClient.setWsdlLocation(this.sts2Url + "?wsdl");
        stsClient.setLocation(this.sts2Url);
        stsClient
                .setServiceName("{http://docs.oasis-open.org/ws-sx/ws-trust/200512}SecurityTokenService");
        stsClient
                .setEndpointName("{http://docs.oasis-open.org/ws-sx/ws-trust/200512}SecurityTokenServicePort");
        stsClient
                .setKeyType("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer");
        stsClient
                .setTokenType("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0");
        stsClient.setAllowRenewing(false);

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        X509Certificate certificate = getCertificate(privateKey, publicKey);
        List<X509Certificate> certificates = new LinkedList<>();
        certificates.add(certificate);
        certificates.add(certificate);

        // Apache CXF specific configuration
        Map<String, Object> properties = stsClient.getProperties();
        properties.put(SecurityConstants.SIGNATURE_USERNAME, "username");
        properties.put(SecurityConstants.CALLBACK_HANDLER,
                new ExampleSecurityPolicyCallbackHandler());
        properties.put(SecurityConstants.SIGNATURE_CRYPTO, new ClientCrypto(
                privateKey, certificates));
        stsClient.setProperties(properties);

        SecurityToken securityToken = stsClient
                .requestSecurityToken("https://demo.app.applies.to");
        LOGGER.debug("security token type: {}", securityToken.getClass().getName());
        Principal principal = securityToken.getPrincipal();
        LOGGER.debug("principal: {}", principal);
        LOGGER.debug("token type: {}", securityToken.getTokenType());
        assertEquals(
                "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0",
                securityToken.getTokenType());
        LOGGER.debug("security token expires: {}", securityToken.getExpires());

        LOGGER.debug("---------------------------------------------------------------");
        stsClient.setEnableAppliesTo(true);
        stsClient
                .setTokenType("http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/Status");
        stsClient.validateSecurityToken(securityToken);
    }
	@Test
    public void testPublicKeyToken() throws Exception {
        SpringBusFactory bf = new SpringBusFactory();
        Bus bus = bf.createBus("cxf_https.xml");
        STSClient stsClient = new STSClient(bus);
        stsClient.setSoap12();
        stsClient.setWsdlLocation(this.sts2Url + "?wsdl");
        stsClient.setLocation(this.sts2Url);
        stsClient
                .setServiceName("{http://docs.oasis-open.org/ws-sx/ws-trust/200512}SecurityTokenService");
        stsClient
                .setEndpointName("{http://docs.oasis-open.org/ws-sx/ws-trust/200512}SecurityTokenServicePort");
        stsClient
                .setKeyType("http://docs.oasis-open.org/ws-sx/ws-trust/200512/PublicKey");
        stsClient
                .setTokenType("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0");
        stsClient.setAllowRenewing(false);

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        X509Certificate certificate = getCertificate(privateKey, publicKey);
        List<X509Certificate> certificates = new LinkedList<>();
        certificates.add(certificate);
        certificates.add(certificate);

        // Apache CXF specific configuration
        Map<String, Object> properties = stsClient.getProperties();
        properties.put(SecurityConstants.SIGNATURE_USERNAME, "username");
        properties.put(SecurityConstants.CALLBACK_HANDLER,
                new ExampleSecurityPolicyCallbackHandler());
        properties.put(SecurityConstants.SIGNATURE_CRYPTO, new ClientCrypto(
                privateKey, certificates));
        // next is for holder of key
        properties.put(SecurityConstants.STS_TOKEN_CRYPTO, new ClientCrypto(
                privateKey, certificates));
        stsClient.setProperties(properties);

        SecurityToken securityToken = stsClient
                .requestSecurityToken("https://demo.app.applies.to");
        Principal principal = securityToken.getPrincipal();
        LOGGER.debug("principal: {}", principal);
        LOGGER.debug("token type: {}", securityToken.getTokenType());
        assertEquals(
                "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0",
                securityToken.getTokenType());
        LOGGER.debug("security token expires: {}", securityToken.getExpires());

        LOGGER.debug("---------------------------------------------------------------");
        stsClient.setEnableAppliesTo(true);
        stsClient
                .setTokenType("http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/Status");
        stsClient.validateSecurityToken(securityToken);
    }
	@Test
    public void testPublicKeyTokenOtherKey() throws Exception {
        SpringBusFactory bf = new SpringBusFactory();
        Bus bus = bf.createBus("cxf_https.xml");
        STSClient stsClient = new STSClient(bus);
        stsClient.setSoap12();
        stsClient.setWsdlLocation(this.sts2Url + "?wsdl");
        stsClient.setLocation(this.sts2Url);
        stsClient
                .setServiceName("{http://docs.oasis-open.org/ws-sx/ws-trust/200512}SecurityTokenService");
        stsClient
                .setEndpointName("{http://docs.oasis-open.org/ws-sx/ws-trust/200512}SecurityTokenServicePort");
        stsClient
                .setKeyType("http://docs.oasis-open.org/ws-sx/ws-trust/200512/PublicKey");
        stsClient
                .setTokenType("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0");
        stsClient.setAllowRenewing(false);

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        X509Certificate certificate = getCertificate(privateKey, publicKey);
        List<X509Certificate> certificates = new LinkedList<>();
        certificates.add(certificate);

        KeyPair hokKeyPair = keyPairGenerator.generateKeyPair();
        PrivateKey hokPrivateKey = hokKeyPair.getPrivate();
        PublicKey hokPublicKey = hokKeyPair.getPublic();
        X509Certificate hokCertificate = getCertificate(hokPrivateKey,
                hokPublicKey);
        List<X509Certificate> hokCertificates = new LinkedList<>();
        hokCertificates.add(hokCertificate);

        // Apache CXF specific configuration
        Map<String, Object> properties = stsClient.getProperties();
        properties.put(SecurityConstants.SIGNATURE_USERNAME, "username");
        properties.put(SecurityConstants.CALLBACK_HANDLER,
                new ExampleSecurityPolicyCallbackHandler());
        properties.put(SecurityConstants.SIGNATURE_CRYPTO, new ClientCrypto(
                privateKey, certificates));
        // next is for holder of key
        properties.put(SecurityConstants.STS_TOKEN_CRYPTO, new ClientCrypto(
                hokPrivateKey, hokCertificates));
        stsClient.setProperties(properties);

        SecurityToken securityToken = stsClient
                .requestSecurityToken("https://demo.app.applies.to");
        Principal principal = securityToken.getPrincipal();
        LOGGER.debug("principal: {}", principal);
        LOGGER.debug("token type: {}", securityToken.getTokenType());
        assertEquals(
                "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0",
                securityToken.getTokenType());
        LOGGER.debug("security token expires: {}", securityToken.getExpires());

        LOGGER.debug("---------------------------------------------------------------");
        stsClient.setEnableAppliesTo(true);
        stsClient
                .setTokenType("http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/Status");
        stsClient.validateSecurityToken(securityToken);
    }
	@Test
	public void testSupportingTokensUsernameToken() throws Exception {
		// get the JAX-WS client
		ExampleService exampleService = new ExampleService();
		ExampleServicePortType port = exampleService.getExampleServicePort();

		// set the web service address on the client stub
		BindingProvider bindingProvider = (BindingProvider) port;
		Map<String, Object> requestContext = bindingProvider
				.getRequestContext();
		requestContext.put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, this.url);

		// Apache CXF specific configuration
		requestContext.put(SecurityConstants.USERNAME, "username");
		requestContext.put(SecurityConstants.PASSWORD, "password");

		// invoke the web service
		String result = port.echo("hello world");
		Assert.assertEquals("username:hello world", result);
	}

	@Test
	public void testSecureConversationBootstrapUsernameToken() throws Exception {
		SpringBusFactory bf = new SpringBusFactory();
		Bus bus = bf.createBus("cxf_https.xml");
		BusFactory.setDefaultBus(bus);
		// get the JAX-WS client
		ExampleService exampleService = new ExampleService();
		ExampleServicePortType port = exampleService.getExampleServicePort6();

		// set the web service address on the client stub
		BindingProvider bindingProvider = (BindingProvider) port;
		Map<String, Object> requestContext = bindingProvider
				.getRequestContext();
		requestContext
				.put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, this.url6);

		// Apache CXF specific configuration
		requestContext.put(SecurityConstants.USERNAME + ".sct", "username");
		requestContext.put(SecurityConstants.PASSWORD + ".sct", "password");

		// invoke the web service
		String result = port.echo("hello world");
		Assert.assertEquals("username:hello world", result);
	}

	@Test
	public void testTransportBindingHttpsTokenSupportingTokensUsernameToken()
			throws Exception {
		SpringBusFactory bf = new SpringBusFactory();
		Bus bus = bf.createBus("cxf-https-trust-all.xml");
		BusFactory.setDefaultBus(bus);
		// get the JAX-WS client
		ExampleService exampleService = new ExampleService();
		ExampleServicePortType port = exampleService.getExampleServicePort2();

		// set the web service address on the client stub
		BindingProvider bindingProvider = (BindingProvider) port;
		Map<String, Object> requestContext = bindingProvider
				.getRequestContext();
		requestContext
				.put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, this.url2);

		// Apache CXF specific configuration
		requestContext.put(SecurityConstants.USERNAME, "username");
		requestContext.put(SecurityConstants.PASSWORD, "password");

		// invoke the web service
		String result = port.echo("hello world");
		Assert.assertEquals("username:hello world", result);

		bus.shutdown(true);
	}

	@Test
	public void testUsernamePasswordCXFSTS() throws Exception {
		SpringBusFactory bf = new SpringBusFactory();
		Bus bus = bf.createBus("cxf_https.xml");
		STSClient stsClient = new STSClient(bus);
		stsClient.setSoap12();
		stsClient.setWsdlLocation(this.stsUsernameUrl + "?wsdl");
		stsClient.setLocation(this.stsUsernameUrl);
		stsClient
				.setServiceName("{http://docs.oasis-open.org/ws-sx/ws-trust/200512}SecurityTokenService");
		stsClient
				.setEndpointName("{http://docs.oasis-open.org/ws-sx/ws-trust/200512}SecurityTokenServicePort");
		stsClient
				.setKeyType("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer");
		stsClient.setTokenType("urn:oasis:names:tc:SAML:2.0:assertion");
		stsClient.setAllowRenewing(false);

		Map<String, Object> properties = stsClient.getProperties();
		properties.put(SecurityConstants.USERNAME, "username");
		properties.put(SecurityConstants.PASSWORD, "password");
		stsClient.setProperties(properties);

		LOGGER.debug("STS location: {}", stsClient.getLocation());
		SecurityToken securityToken = stsClient
				.requestSecurityToken("https://demo.app.applies.to");
		Principal principal = securityToken.getPrincipal();
		LOGGER.debug("principal: {}", principal);
		LOGGER.debug("token type: {}", securityToken.getTokenType());
		assertEquals("urn:oasis:names:tc:SAML:2.0:assertion",
				securityToken.getTokenType());
		LOGGER.debug("security token expires: {}", securityToken.getExpires());

		bus.shutdown(true);
	}

	@Test
	public void testTransportBindingHttpsTokenSupportingTokensSamlToken()
			throws Exception {
		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
				.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder documentBuilder = documentBuilderFactory
				.newDocumentBuilder();
		Document document = documentBuilder
				.parse(SamlClientCallbackHandler.class
						.getResourceAsStream("/saml-assertion.xml"));
		Element assertionElement = document.getDocumentElement();

		SpringBusFactory bf = new SpringBusFactory();
		Bus bus = bf.createBus("cxf-https-trust-all.xml");
		BusFactory.setDefaultBus(bus);
		// get the JAX-WS client
		ExampleService exampleService = new ExampleService();
		ExampleServicePortType port = exampleService.getExampleServicePort3();

		SecurityDecorator securityDecorator = new SecurityDecorator();
		BindingProvider bindingProvider = (BindingProvider) port;
		securityDecorator
				.decorate(bindingProvider, assertionElement, this.url3);

		// invoke the web service
		String result = port.echo("hello world");
		Assert.assertEquals("hello world", result);

		bus.shutdown(true);
	}

	@Test
	public void testTransportBindingHttpsTokenSupportingTokensX509Token()
			throws Exception {
		SpringBusFactory bf = new SpringBusFactory();
		Bus bus = bf.createBus("cxf-https-trust-all.xml");
		BusFactory.setDefaultBus(bus);
		// get the JAX-WS client
		ExampleService exampleService = new ExampleService();
		ExampleServicePortType port = exampleService.getExampleServicePort4();

		// set the web service address on the client stub
		BindingProvider bindingProvider = (BindingProvider) port;
		Map<String, Object> requestContext = bindingProvider
				.getRequestContext();
		requestContext
				.put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, this.url4);

		Binding binding = bindingProvider.getBinding();
		List<Handler> handlerChain = binding.getHandlerChain();
		handlerChain.add(new LoggingSOAPHandler());
		binding.setHandlerChain(handlerChain);

		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();
		X509Certificate certificate = getCertificate(privateKey, publicKey);

		// Apache CXF specific configuration
		requestContext.put(SecurityConstants.SIGNATURE_USERNAME, "username");
		requestContext.put(SecurityConstants.CALLBACK_HANDLER,
				new ExampleSecurityPolicyCallbackHandler());
		requestContext.put(
				SecurityConstants.SIGNATURE_CRYPTO,
				new ClientCrypto(privateKey, Collections
						.singletonList(certificate)));

		// invoke the web service
		String result = port.echo("hello world");
		Assert.assertEquals("CN=Test:hello world", result);

		bus.shutdown(true);
	}

	@Test
    public void testTransportBindingHttpsTokenSupportingTokensSamlTokenViaSTS()
            throws Exception {
        SpringBusFactory bf = new SpringBusFactory();
        Bus bus = bf.createBus("cxf-https-trust-all.xml");
        BusFactory.setDefaultBus(bus);
        // get the JAX-WS client
        ExampleService exampleService = new ExampleService();
        ExampleServicePortType port = exampleService.getExampleServicePort5();

        // set the web service address on the client stub
        BindingProvider bindingProvider = (BindingProvider) port;
        Map<String, Object> requestContext = bindingProvider
                .getRequestContext();
        requestContext
                .put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, this.url5);

        // Apache CXF specific configuration
        STSClient stsClient = new STSClient(bus);
        requestContext.put(SecurityConstants.STS_CLIENT, stsClient);
        stsClient.setWsdlLocation(this.sts2Url + "?wsdl");
        stsClient
                .setServiceName("{http://docs.oasis-open.org/ws-sx/ws-trust/200512}SecurityTokenService");
        stsClient
                .setEndpointName("{http://docs.oasis-open.org/ws-sx/ws-trust/200512}SecurityTokenServicePort");
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        X509Certificate certificate = getCertificate(privateKey, publicKey);
        List<X509Certificate> certificates = new LinkedList<>();
        certificates.add(certificate);

        Map<String, Object> properties = stsClient.getProperties();
        properties.put(SecurityConstants.SIGNATURE_USERNAME, "username");
        properties.put(SecurityConstants.CALLBACK_HANDLER,
                new ExampleSecurityPolicyCallbackHandler());
        properties.put(SecurityConstants.SIGNATURE_CRYPTO, new ClientCrypto(
                privateKey, certificates));
        stsClient.setProperties(properties);

        ExampleServiceMBean.trustAddress(this.url5);

        // invoke the web service
        String result = port.echo("hello world");
        Assert.assertEquals("custom-CN=Test:hello world", result);

        bus.shutdown(true);
    }
	@Test
    public void testTransportBindingHttpsTokenSupportingTokensSamlTokenViaSTSWithMEX()
            throws Exception {
        SpringBusFactory bf = new SpringBusFactory();
        Bus bus = bf.createBus("cxf-https-trust-all.xml");
        BusFactory.setDefaultBus(bus);
        // get the JAX-WS client
        ExampleService exampleService = new ExampleService();
        ExampleServicePortType port = exampleService.getExampleServicePort7();

        // set the web service address on the client stub
        BindingProvider bindingProvider = (BindingProvider) port;
        Map<String, Object> requestContext = bindingProvider
                .getRequestContext();
        requestContext
                .put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, this.url7);

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        X509Certificate certificate = getCertificate(privateKey, publicKey);
        List<X509Certificate> certificates = new LinkedList<>();
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

        ExampleServiceMBean.trustAddress(this.url7);

        // invoke the web service
        String result = port.echo("hello world");
        Assert.assertEquals("custom-CN=Test:hello world", result);

        bus.shutdown(true);
    }
	@Test
    public void testTransportBindingHttpsTokenSupportingTokensSamlTokenViaSTSWithMEXAndClaims()
            throws Exception {
        SpringBusFactory bf = new SpringBusFactory();
        Bus bus = bf.createBus("cxf-https-trust-all.xml");
        BusFactory.setDefaultBus(bus);
        // get the JAX-WS client
        ExampleService exampleService = new ExampleService();
        ExampleServicePortType port = exampleService.getExampleServicePort8();

        // set the web service address on the client stub
        BindingProvider bindingProvider = (BindingProvider) port;
        Map<String, Object> requestContext = bindingProvider
                .getRequestContext();
        requestContext
                .put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, this.url8);

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        X509Certificate certificate = getCertificate(privateKey, publicKey);
        List<X509Certificate> certificates = new LinkedList<>();
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
        requestContext.put(SecurityConstants.STS_TOKEN_ACT_AS,
                new ActAsCallbackHandler());

        ExampleServiceMBean.trustAddress(this.url8);

        // invoke the web service
        String result = port.echo("hello world");
        Assert.assertEquals("custom-CN=Test:hello world", result);

        bus.shutdown(true);
    }
	private static int getFreePort() throws Exception {
        try (ServerSocket serverSocket = new ServerSocket(0)) {
            return serverSocket.getLocalPort();
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
