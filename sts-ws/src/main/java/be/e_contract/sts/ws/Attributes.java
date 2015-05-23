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
 * Enumeration of supported attributes for the ActAs input SAML assertion.
 * 
 * @author Frank Cornelis
 * 
 */
public enum Attributes {

	SOFTWARE_KEY("urn:be:e-contract:iam:claims:self-claimed:software-key"),

	OFFICE_KEY("urn:be:e-contract:iam:claims:self-claimed:office-key"),

	IDENTITY("urn:be:e-contract:sts:eid:identity"),

	IDENTITY_SIGNATURE("urn:be:e-contract:sts:eid:identity-signature"),

	NATIONAL_REGISTRATION_CERTIFICATE("urn:be:e-contract:sts:eid:nr-cert"),

	ADDRESS("urn:be:e-contract:sts:eid:address"),

	ADDRESS_SIGNATURE("urn:be:e-contract:sts:eid:address-signature"),

	PHOTO("urn:be:e-contract:sts:eid:photo");

	private final String name;

	private Attributes(String name) {
		this.name = name;
	}

	/**
	 * Gives back the Name value of the attribute type.
	 * 
	 * @return the Name as string.
	 */
	public String getName() {
		return this.name;
	}
}
