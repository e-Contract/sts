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

	private String officeKey;

	private String softwareKey;

	private byte[] identity;

	private byte[] identitySignature;

	private byte[] nationalRegistrationCertificate;

	private byte[] address;

	private byte[] addressSignature;

	private byte[] photo;

	private boolean useActAsToken() {
		return this.officeKey != null || this.softwareKey != null
				|| this.identity != null || this.identitySignature != null
				|| this.address != null || this.addressSignature != null
				|| this.photo != null
				|| this.nationalRegistrationCertificate != null;
	}

	public String getOfficeKey() {
		return this.officeKey;
	}

	public void setOfficeKey(String officeKey) {
		this.officeKey = officeKey;
	}

	public String getSoftwareKey() {
		return this.softwareKey;
	}

	public void setSoftwareKey(String softwareKey) {
		this.softwareKey = softwareKey;
	}

	public byte[] getIdentity() {
		return this.identity;
	}

	public void setIdentity(byte[] identity) {
		this.identity = identity;
	}

	public byte[] getIdentitySignature() {
		return this.identitySignature;
	}

	public void setIdentitySignature(byte[] identitySignature) {
		this.identitySignature = identitySignature;
	}

	public byte[] getNationalRegistrationCertificate() {
		return this.nationalRegistrationCertificate;
	}

	public void setNationalRegistrationCertificate(
			byte[] nationalRegistrationCertificate) {
		this.nationalRegistrationCertificate = nationalRegistrationCertificate;
	}

	public byte[] getAddress() {
		return this.address;
	}

	public void setAddress(byte[] address) {
		this.address = address;
	}

	public byte[] getAddressSignature() {
		return this.addressSignature;
	}

	public void setAddressSignature(byte[] addressSignature) {
		this.addressSignature = addressSignature;
	}

	public byte[] getPhoto() {
		return this.photo;
	}

	public void setPhoto(byte[] photo) {
		this.photo = photo;
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
		if (useActAsToken()) {
			// only when an attribute has been set
			requestContext.put(SecurityConstants.STS_TOKEN_ACT_AS,
					new ActAsCallbackHandler(this));
		}
	}
}
