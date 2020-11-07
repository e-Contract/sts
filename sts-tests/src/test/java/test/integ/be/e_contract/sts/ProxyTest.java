/*
 * eID Security Token Service Project.
 * Copyright (C) 2014-2020 e-Contract.be BV.
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

import java.security.Security;

import javax.xml.ws.BindingProvider;

import org.apache.cxf.Bus;
import org.apache.cxf.BusFactory;
import org.apache.cxf.bus.spring.SpringBusFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.e_contract.sts.client.cxf.SecurityDecorator;
import be.e_contract.sts.example.ws.jaxws.ExampleService;
import be.e_contract.sts.example.ws.jaxws.ExampleServicePortType;
import be.fedict.commons.eid.jca.BeIDProvider;

/**
 * Example for HTTP proxy.
 * 
 * @author Frank Cornelis
 */
public class ProxyTest {

	private static final Logger LOGGER = LoggerFactory.getLogger(ProxyTest.class);

	@BeforeAll
	public static void setUp() throws Exception {
		Security.addProvider(new BeIDProvider());
	}

	@Test
	public void testHTTPProxy() throws Exception {
		SpringBusFactory bf = new SpringBusFactory();
		Bus bus = bf.createBus("cxf-proxy.xml");
		BusFactory.setDefaultBus(bus);

		ExampleService exampleService = new ExampleService();
		ExampleServicePortType port = exampleService.getExampleServicePort();

		SecurityDecorator securityDecorator = new SecurityDecorator();
		securityDecorator.decorate((BindingProvider) port, "https://www.e-contract.be/iam/example");

		// invoke the web service
		String result = port.holderOfKeyEcho("hello world");
		LOGGER.debug("result: " + result);
	}
}
