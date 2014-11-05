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

package be.e_contract.sts.ws;

import java.net.URL;

import javax.xml.namespace.QName;

import be.e_contract.sts.ws.jaxws.SecurityTokenService;

public class SecurityTokenServiceFactory {

	private SecurityTokenServiceFactory() {
		super();
	}

	public static SecurityTokenService newInstance() {
		URL wsdlLocation = SecurityTokenServiceFactory.class
				.getResource("/ws-trust-1.3.wsdl");
		QName SECURITYTOKENSERVICE_QNAME = new QName(
				"http://docs.oasis-open.org/ws-sx/ws-trust/200512",
				"SecurityTokenService");
		SecurityTokenService securityTokenService = new SecurityTokenService(
				wsdlLocation, SECURITYTOKENSERVICE_QNAME);
		return securityTokenService;
	}
}
