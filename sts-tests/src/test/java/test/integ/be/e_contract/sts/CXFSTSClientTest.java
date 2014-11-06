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

import java.io.IOException;
import java.net.URL;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

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

import org.apache.cxf.Bus;
import org.apache.cxf.BusFactory;
import org.apache.cxf.databinding.source.SourceDataBinding;
import org.apache.cxf.endpoint.Endpoint;
import org.apache.cxf.endpoint.EndpointImpl;
import org.apache.cxf.service.Service;
import org.apache.cxf.service.model.EndpointInfo;
import org.apache.cxf.ws.security.trust.STSClient;
import org.apache.cxf.wsdl11.WSDLServiceFactory;
import org.apache.ws.security.WSPasswordCallback;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
	public void testCXFSTSClient() throws Exception {
		Bus bus = BusFactory.getDefaultBus();
		STSClient stsClient = new STSClient(bus);
		stsClient.setSoap12();
		URL wsdlLocation = CXFSTSClientTest.class
				.getResource("/ws-trust-1.3.wsdl");
		// stsClient.setWsdlLocation(wsdlLocation.toURI().toURL().toString());
		stsClient.setLocation("https://localhost/iam/sts");
		// stsClient.setServiceQName(new QName(
		// "http://docs.oasis-open.org/ws-sx/ws-trust/200512",
		// "SecurityTokenService"));
		// stsClient.setEndpointQName(new QName(
		// "http://docs.oasis-open.org/ws-sx/ws-trust/200512",
		// "SecurityTokenService"));
		stsClient
				.setAddressingNamespace("http://schemas.xmlsoap.org/ws/2004/08/addressing");
		stsClient
				.setKeyType("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer");
		stsClient.setTokenType("urn:oasis:names:tc:SAML:2.0:assertion");
		stsClient.setAllowRenewing(false);

		// Map<String, Object> properties = stsClient.getProperties();
		// properties.put(SecurityConstants.STS_TOKEN_USERNAME, "username");
		// properties.put(SecurityConstants.CALLBACK_HANDLER,
		// new UTCallbackHandler());
		// stsClient.setProperties(properties);

		stsClient.requestSecurityToken("https://demo.app.applies.to");
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
		QName serviceName = new QName(
				"urn:be:e-contract:sts:example",
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
