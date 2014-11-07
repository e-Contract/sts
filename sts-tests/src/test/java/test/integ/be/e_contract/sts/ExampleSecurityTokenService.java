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

import javax.jws.HandlerChain;
import javax.jws.WebService;

import org.apache.cxf.annotations.EndpointProperties;
import org.apache.cxf.annotations.EndpointProperty;

import be.e_contract.sts.ws.jaxb.wst.RequestSecurityTokenResponseCollectionType;
import be.e_contract.sts.ws.jaxb.wst.RequestSecurityTokenType;
import be.e_contract.sts.ws.jaxws.SecurityTokenServicePort;

@WebService(endpointInterface = "be.e_contract.sts.ws.jaxws.SecurityTokenServicePort", targetNamespace = "http://docs.oasis-open.org/ws-sx/ws-trust/200512", serviceName = "SecurityTokenService", wsdlLocation = "ws-trust-1.3.wsdl", portName = "SecurityTokenServicePort")
@HandlerChain(file = "/example-ws-handlers.xml")
@EndpointProperties({ @EndpointProperty(key = "ws-security.signature.properties", value = "signature.properties") })
public class ExampleSecurityTokenService implements SecurityTokenServicePort {

	@Override
	public RequestSecurityTokenResponseCollectionType requestSecurityToken(
			RequestSecurityTokenType request) {
		return null;
	}
}
