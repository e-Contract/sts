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

/**
 * Enumeration holding the eID IP-STS supported claim types.
 * 
 * @author Frank Cornelis
 * 
 */
public enum ClaimTypes {

	SOFTWARE_KEY("urn:be:e-contract:iam:claims:self-claimed:software-key"),

	OFFICE_KEY("urn:be:e-contract:iam:claims:self-claimed:office-key"),

	NAME("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"),

	SURNAME("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"),

	GIVENNAME("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"),

	DN(
			"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/x500distinguishedname"),

	COUNTRY("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/country"),

	DATE_OF_BIRTH(
			"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/dateofbirth"),

	GENDER("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/gender"),

	LOCALITY("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/locality"),

	POSTAL_CODE(
			"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/postalcode"),

	STREET_ADDRESS(
			"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/streetaddress");

	private final String uri;

	private ClaimTypes(String uri) {
		this.uri = uri;
	}

	/**
	 * Gives back the Uri value of the claim type.
	 * 
	 * @return the Uri as string.
	 */
	public String getUri() {
		return this.uri;
	}
}
