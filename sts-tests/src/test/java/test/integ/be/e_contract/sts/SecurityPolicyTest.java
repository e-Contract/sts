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

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Map;

import javax.xml.ws.BindingProvider;
import javax.xml.ws.Endpoint;

import org.apache.cxf.Bus;
import org.apache.cxf.BusFactory;
import org.apache.cxf.bus.spring.SpringBusFactory;
import org.apache.cxf.ws.security.SecurityConstants;
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

import be.e_contract.sts.example.ExampleService;
import be.e_contract.sts.example.ExampleServicePortType;

public class SecurityPolicyTest {

	private String url;

	private Endpoint endpoint;

	private String url2;

	private Endpoint endpoint2;

	private String url3;

	private Endpoint endpoint3;

	@Before
	public void setUp() throws Exception {
		int sslFreePort = getFreePort();

		System.setProperty("testutil.ports.Server",
				Integer.toString(sslFreePort));

		SpringBusFactory bf = new SpringBusFactory();
		Bus bus = bf.createBus("jaxws-server.xml");
		BusFactory.setDefaultBus(bus);

		this.url2 = "https://localhost:" + sslFreePort + "/example/ws2";
		this.endpoint2 = Endpoint.publish(this.url2,
				new ExampleSecurityPolicyServicePortImpl2());

		this.url3 = "https://localhost:" + sslFreePort + "/example/ws3";
		this.endpoint3 = Endpoint.publish(this.url3,
				new ExampleSecurityPolicyServicePortImpl3());

		int freePort = getFreePort();
		this.url = "http://localhost:" + freePort + "/example/ws";
		this.endpoint = Endpoint.publish(this.url,
				new ExampleSecurityPolicyServicePortImpl());
	}

	@After
	public void tearDown() throws Exception {
		this.endpoint.stop();
		this.endpoint2.stop();
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
	public void testTransportBindingHttpsTokenSupportingTokensUsernameToken()
			throws Exception {
		SpringBusFactory bf = new SpringBusFactory();
		Bus bus = bf.createBus("cxf_https.xml");
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
	public void testTransportBindingHttpsTokenSupportingTokensSamlToken()
			throws Exception {
		SpringBusFactory bf = new SpringBusFactory();
		Bus bus = bf.createBus("cxf_https.xml");
		BusFactory.setDefaultBus(bus);
		// get the JAX-WS client
		ExampleService exampleService = new ExampleService();
		ExampleServicePortType port = exampleService.getExampleServicePort3();

		// set the web service address on the client stub
		BindingProvider bindingProvider = (BindingProvider) port;
		Map<String, Object> requestContext = bindingProvider
				.getRequestContext();
		requestContext
				.put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, this.url3);

		// Apache CXF specific configuration
		requestContext.put(SecurityConstants.SAML_CALLBACK_HANDLER,
				new SamlClientCallbackHandler());

		// invoke the web service
		String result = port.echo("hello world");
		Assert.assertEquals("hello world", result);

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
