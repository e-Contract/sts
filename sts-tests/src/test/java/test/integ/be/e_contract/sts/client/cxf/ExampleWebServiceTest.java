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

package test.integ.be.e_contract.sts.client.cxf;

import java.security.Security;

import javax.xml.ws.BindingProvider;

import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.e_contract.sts.client.cxf.SecurityDecorator;
import be.e_contract.sts.example.ws.ExampleServiceFactory;
import be.e_contract.sts.example.ws.jaxws.ExampleService;
import be.e_contract.sts.example.ws.jaxws.ExampleServicePortType;
import be.fedict.commons.eid.jca.BeIDProvider;

public class ExampleWebServiceTest {

	private static final Logger LOGGER = LoggerFactory
			.getLogger(ExampleWebServiceTest.class);

	@Before
	public void setUp() throws Exception {
		Security.addProvider(new BeIDProvider());
	}

	@Test
	public void testInvocation() throws Exception {
		ExampleService exampleService = ExampleServiceFactory.newInstance();
		ExampleServicePortType port = exampleService.getExampleServicePort();

		SecurityDecorator securityDecorator = new SecurityDecorator(
				"example-office-key", "example-software-key");
		securityDecorator.decorate((BindingProvider) port,
				"https://www.e-contract.be/iam/example");

		String result = port.echoWithClaims("hello world");
		LOGGER.debug("result: " + result);
	}
}
