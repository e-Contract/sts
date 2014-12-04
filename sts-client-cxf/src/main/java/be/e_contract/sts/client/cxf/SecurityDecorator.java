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

package be.e_contract.sts.client.cxf;

import java.util.Map;

import javax.xml.ws.BindingProvider;

import org.apache.cxf.ws.security.SecurityConstants;

/**
 * This decorator helps to enable the STS security model on JAX-WS clients using
 * Apache CXF.
 * 
 * @author Frank Cornelis
 *
 */
public class SecurityDecorator {

	private final String officeKey;

	private final String softwareKey;

	public SecurityDecorator(String officeKey, String softwareKey) {
		this.officeKey = officeKey;
		this.softwareKey = softwareKey;
	}

	/**
	 * Enables the STS security configuration on the given JAX-WS port.
	 * 
	 * @param bindingProvider
	 *            the JAX-WS port.
	 * @param endpointLocation
	 *            the location of the web service.
	 */
	public void decorate(BindingProvider bindingProvider,
			String endpointLocation) {
		Map<String, Object> requestContext = bindingProvider
				.getRequestContext();
		requestContext.put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY,
				endpointLocation);

		requestContext.put(SecurityConstants.STS_CLIENT_SOAP12_BINDING, "true");
		requestContext
				.put(SecurityConstants.SIGNATURE_CRYPTO, new BeIDCrypto());
		requestContext.put(SecurityConstants.STS_TOKEN_USE_CERT_FOR_KEYINFO,
				"true");

		// next are not really used in the context of eID
		requestContext.put(SecurityConstants.SIGNATURE_USERNAME, "whatever");
		requestContext.put(SecurityConstants.CALLBACK_HANDLER,
				new PasswordCallbackHandler());

		requestContext.put(
				SecurityConstants.PREFER_WSMEX_OVER_STS_CLIENT_CONFIG, "true");
		requestContext.put(SecurityConstants.STS_TOKEN_ACT_AS,
				new ActAsCallbackHandler(this.officeKey, this.softwareKey));
	}
}
