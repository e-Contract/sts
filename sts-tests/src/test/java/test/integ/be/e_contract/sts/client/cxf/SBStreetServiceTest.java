/*
 * eID Security Token Service Project.
 * Copyright (C) 2015 e-Contract.be BVBA.
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

import be.advocaat.services.street.v1.EchoRequestType;
import be.advocaat.services.street.v1.EchoResponseType;
import be.advocaat.services.street.v1.IService;
import be.advocaat.services.street.v1.SBStreetService;
import be.e_contract.sts.client.cxf.SecurityDecorator;
import be.e_contract.sts.example.ws.ExampleServiceFactory;
import be.fedict.commons.eid.jca.BeIDProvider;
import java.net.URL;
import java.security.Security;
import javax.xml.namespace.QName;
import javax.xml.ws.BindingProvider;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Example Apache CXF client for the SBStreetService web service.
 * 
 * @author Frank Cornelis
 */
public class SBStreetServiceTest {

	private static final Logger LOGGER = LoggerFactory
			.getLogger(SBStreetServiceTest.class);

	@Before
	public void setUp() throws Exception {
		Security.addProvider(new BeIDProvider());
	}

	@Test
	public void testEcho() throws Exception {
		URL wsdlLocation = ExampleServiceFactory.class
				.getResource("/SBStreetService.wsdl");
		QName SBSTREETSERVICE_QNAME = new QName(
				"http://services.advocaat.be/street/v1", "SBStreetService");
		SBStreetService streetService = new SBStreetService(wsdlLocation,
				SBSTREETSERVICE_QNAME);
		IService port = streetService.getSBStreetServicePort();

		SecurityDecorator securityDecorator = new SecurityDecorator();
		securityDecorator.setOfficeKey("example-office-key");
		securityDecorator.setSoftwareKey("example-software-key");
		securityDecorator
				.decorate((BindingProvider) port,
						"https://services.test.advocaat.be/OVB.Services.SB.Street/Service.svc");

		EchoRequestType echoRequest = new EchoRequestType();
		echoRequest.setRequest("hello world");
		EchoResponseType echoResponse = port.echo(echoRequest);
		LOGGER.debug("response: {}", echoResponse.getResponse());
	}
}
