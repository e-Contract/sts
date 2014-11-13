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

import java.security.Principal;

import javax.annotation.Resource;
import javax.jws.HandlerChain;
import javax.jws.WebService;
import javax.xml.ws.WebServiceContext;

import org.apache.cxf.annotations.EndpointProperties;
import org.apache.cxf.annotations.EndpointProperty;

import be.e_contract.sts.example.ExampleServicePortType;

@WebService(endpointInterface = "be.e_contract.sts.example.ExampleServicePortType", targetNamespace = "urn:be:e-contract:sts:example", serviceName = "ExampleService", wsdlLocation = "example-security-policy.wsdl", portName = "ExampleServicePort6")
@EndpointProperties({ @EndpointProperty(key = "ws-security.callback-handler.sct", value = "test.integ.be.e_contract.sts.ExampleSecurityPolicyCallbackHandler") })
@HandlerChain(file = "/example-ws-handlers.xml")
public class ExampleSecurityPolicyServicePortImpl6 implements
		ExampleServicePortType {

	@Resource
	private WebServiceContext context;

	@Override
	public String echo(String echoRequest) {
		Principal userPrincipal = this.context.getUserPrincipal();
		String username = userPrincipal.getName();
		return username + ":" + echoRequest;
	}
}
