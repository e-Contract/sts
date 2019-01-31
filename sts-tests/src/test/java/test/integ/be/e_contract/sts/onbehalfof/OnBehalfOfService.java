/*
 * eID Security Token Service Project.
 * Copyright (C) 2019 e-Contract.be BVBA.
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

package test.integ.be.e_contract.sts.onbehalfof;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.apache.ws.security.WSSecurityException;

/**
 * Interface for OnBehalfOf STS service.
 * 
 * @author Frank Cornelis
 *
 */
public interface OnBehalfOfService {

	/**
	 * Gives back the STS issuer name.
	 * 
	 * @return
	 */
	String getIssuer();

	/**
	 * Gives back the private key of the STS issuer.
	 * 
	 * @return
	 */
	PrivateKey getPrivateKey();

	/**
	 * Gives back the X509 certificate of the STS issuer.
	 * 
	 * @return
	 */
	X509Certificate getCertificate();

	/**
	 * Verifies the OnBehalfOf SAML assertion signing certificate.
	 * 
	 * @param certificate
	 * @throws WSSecurityException
	 */
	boolean verifyTrust(X509Certificate callerCertificate, X509Certificate certificate) throws WSSecurityException;

	/**
	 * Get the default lifetime in seconds for issued SAML token where requestor
	 * doesn't specify a lifetime element
	 * 
	 * @return the lifetime in seconds
	 */
	long getLifetime(X509Certificate callerCertificate);

	/**
	 * Get the maximum lifetime in seconds for issued SAML token if requestor
	 * specifies lifetime element
	 * 
	 * @return the maximum lifetime in seconds
	 */
	long getMaxLifetime(X509Certificate callerCertificate);

	boolean isAddressInEndpoints(X509Certificate callerCertificate, String address);
}
