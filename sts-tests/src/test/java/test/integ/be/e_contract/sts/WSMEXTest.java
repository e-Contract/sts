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

import java.io.StringWriter;
import java.security.SecureRandom;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;

import org.apache.cxf.Bus;
import org.apache.cxf.BusFactory;
import org.apache.cxf.binding.soap.SoapBindingConstants;
import org.apache.cxf.bus.spring.SpringBusFactory;
import org.apache.cxf.jaxws.JaxWsProxyFactoryBean;
import org.apache.cxf.ws.mex.MetadataExchange;
import org.apache.cxf.ws.mex.model._2004_09.Metadata;
import org.apache.cxf.ws.mex.model._2004_09.ObjectFactory;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import test.integ.be.e_contract.sts.CXFSTSClientTest.MyHostnameVerifier;
import test.integ.be.e_contract.sts.CXFSTSClientTest.MyTrustManager;

public class WSMEXTest {

	private static final Logger LOGGER = LoggerFactory
			.getLogger(WSMEXTest.class);

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
		
		SpringBusFactory bf = new SpringBusFactory();
		Bus bus = bf.createBus("cxf-https-trust-all.xml");
		BusFactory.setDefaultBus(bus);
	}
	
	@Test
	public void testRetrieveMex() throws Exception {
		JaxWsProxyFactoryBean proxyFac = new JaxWsProxyFactoryBean();
		proxyFac.setBindingId(SoapBindingConstants.SOAP12_BINDING_ID);
		proxyFac.setAddress("https://localhost/iam/sts/mex");
		MetadataExchange exc = proxyFac.create(MetadataExchange.class);
		Metadata metadata = exc.get2004();

		JAXBContext context = JAXBContext.newInstance(ObjectFactory.class);
		Marshaller marshaller = context.createMarshaller();

		StringWriter stringWriter = new StringWriter();
		marshaller.marshal(metadata, stringWriter);
		LOGGER.debug(stringWriter.toString());
	}
}
