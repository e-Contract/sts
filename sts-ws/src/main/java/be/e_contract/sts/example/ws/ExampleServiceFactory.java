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

package be.e_contract.sts.example.ws;

import java.net.URL;

import javax.xml.namespace.QName;

import be.e_contract.sts.example.ws.jaxws.ExampleService;

public class ExampleServiceFactory {

	private ExampleServiceFactory() {
		super();
	}

	public static ExampleService newInstance() {
		URL wsdlLocation = ExampleServiceFactory.class
				.getResource("/example.wsdl");
		QName EXAMPLESERVICE_QNAME = new QName("urn:be:e-contract:sts:example",
				"ExampleService");
		ExampleService securityTokenService = new ExampleService(wsdlLocation,
				EXAMPLESERVICE_QNAME);
		return securityTokenService;
	}
}
