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

import java.io.File;
import java.io.IOException;
import java.security.KeyStore;
import java.security.Principal;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
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
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.e_contract.sts.example.ws.jaxws.ExampleService;
import be.e_contract.sts.example.ws.jaxws.ExampleServicePortType;
import be.fedict.commons.eid.jca.BeIDProvider;

public class CXFSTSClientTest {

	private static final Logger LOGGER = LoggerFactory
			.getLogger(CXFSTSClientTest.class);

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

		private static final Logger LOGGER = LoggerFactory
				.getLogger(MyTrustManager.class);

		@Override
		public void checkClientTrusted(X509Certificate[] arg0, String arg1)
				throws CertificateException {
		}

		@Override
		public void checkServerTrusted(X509Certificate[] certs, String arg1)
				throws CertificateException {
			LOGGER.debug("server cert: {}", certs[0].toString());
		}

		@Override
		public X509Certificate[] getAcceptedIssuers() {
			return null;
		}
	}

	@Test
	public void testExampleWebService() throws Exception {
		SpringBusFactory bf = new SpringBusFactory();
		Bus bus = bf.createBus("cxf-https-trust-all.xml");
		BusFactory.setDefaultBus(bus);
		// get the JAX-WS client
		ExampleService exampleService = new ExampleService();
		ExampleServicePortType port = exampleService.getExampleServicePort();

		// set the web service address on the client stub
		BindingProvider bindingProvider = (BindingProvider) port;
		Map<String, Object> requestContext = bindingProvider
				.getRequestContext();
		requestContext.put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY,
				"https://localhost/iam/example");

		requestContext.put(SecurityConstants.STS_CLIENT_SOAP12_BINDING, "true");
		requestContext
				.put(SecurityConstants.SIGNATURE_CRYPTO, new BeIDCrypto());
		requestContext.put(SecurityConstants.STS_TOKEN_USE_CERT_FOR_KEYINFO,
				"true");
		requestContext.put(SecurityConstants.SIGNATURE_USERNAME, "username");
		requestContext.put(SecurityConstants.CALLBACK_HANDLER,
				new ExampleSecurityPolicyCallbackHandler());
		requestContext.put(
				SecurityConstants.PREFER_WSMEX_OVER_STS_CLIENT_CONFIG, "true");

		// invoke the web service
		String result = port.echo("hello world");
		LOGGER.debug("result: " + result);

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

		Client client = stsClient.getClient();
		HTTPConduit httpConduit = (HTTPConduit) client.getConduit();
		TLSClientParameters tlsParams = new TLSClientParameters();
		tlsParams.setSecureSocketProtocol("SSL");
		tlsParams.setDisableCNCheck(true);
		tlsParams.setTrustManagers(new TrustManager[] { new MyTrustManager() });
		httpConduit.setTlsClientParameters(tlsParams);

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

		LOGGER.debug("---------------------------------------------------------------");
		stsClient.setEnableAppliesTo(true);
		stsClient
				.setTokenType("http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/Status");
		stsClient.validateSecurityToken(securityToken);
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
		QName serviceName = new QName(
				"http://docs.oasis-open.org/ws-sx/ws-trust/200512",
				"SecurityTokenService");
		WSDLServiceFactory factory = new WSDLServiceFactory(bus, wsdlLocation,
				serviceName);
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
		String wsdlLocation = CXFSTSClientTest.class
				.getResource("/example-security-policy.wsdl").toURI().toURL()
				.toString();
		QName serviceName = new QName("urn:be:e-contract:sts:example",
				"ExampleService");
		WSDLServiceFactory factory = new WSDLServiceFactory(bus, wsdlLocation,
				serviceName);
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
		QName serviceName = new QName(
				"http://docs.oasis-open.org/ws-sx/ws-trust/200512",
				"SecurityTokenService");
		WSDLServiceFactory factory = new WSDLServiceFactory(bus, wsdlLocation,
				serviceName);
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
		public void handle(Callback[] callbacks) throws IOException,
				UnsupportedCallbackException {
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
}
