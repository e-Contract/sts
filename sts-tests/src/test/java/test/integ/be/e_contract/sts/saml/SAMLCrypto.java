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

package test.integ.be.e_contract.sts.saml;

import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Properties;

import javax.security.auth.callback.CallbackHandler;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SAMLCrypto implements Crypto {

	private static final Logger LOGGER = LoggerFactory.getLogger(SAMLCrypto.class);

	public SAMLCrypto(Properties map, ClassLoader loader) {
		// required constructor
	}

	@Override
	public String getCryptoProvider() {
		LOGGER.debug("getCryptoProvider");
		return null;
	}

	@Override
	public void setCryptoProvider(String provider) {
		LOGGER.debug("setCryptoProvider");
	}

	@Override
	public String getDefaultX509Identifier() throws WSSecurityException {
		LOGGER.debug("getDefaultX509Identifier");
		return null;
	}

	@Override
	public void setDefaultX509Identifier(String identifier) {
		LOGGER.debug("setDefaultX509Identifier");

	}

	@Override
	public void setCertificateFactory(String provider, CertificateFactory certFactory) {
		LOGGER.debug("setCertificateFactory");

	}

	@Override
	public CertificateFactory getCertificateFactory() throws WSSecurityException {
		LOGGER.debug("getCertificateFactory");
		return null;
	}

	@Override
	public X509Certificate loadCertificate(InputStream in) throws WSSecurityException {
		LOGGER.debug("loadCertificate");
		return null;
	}

	@Override
	public byte[] getSKIBytesFromCert(X509Certificate cert) throws WSSecurityException {
		LOGGER.debug("getSKIBytesFromCert");
		return null;
	}

	@Override
	public byte[] getBytesFromCertificates(X509Certificate[] certs) throws WSSecurityException {
		LOGGER.debug("getBytesFromCertificates");
		return null;
	}

	@Override
	public X509Certificate[] getCertificatesFromBytes(byte[] data) throws WSSecurityException {
		LOGGER.debug("getCertificatesFromBytes");
		return null;
	}

	@Override
	public X509Certificate[] getX509Certificates(CryptoType cryptoType) throws WSSecurityException {
		LOGGER.debug("getX509Certificates");
		return null;
	}

	@Override
	public String getX509Identifier(X509Certificate cert) throws WSSecurityException {
		LOGGER.debug("getX509Identifier");
		return null;
	}

	@Override
	public PrivateKey getPrivateKey(X509Certificate certificate, CallbackHandler callbackHandler)
			throws WSSecurityException {
		LOGGER.debug("getPrivateKey");
		return null;
	}

	@Override
	public PrivateKey getPrivateKey(String identifier, String password) throws WSSecurityException {
		LOGGER.debug("getPrivateKey");
		return null;
	}

	@Override
	public boolean verifyTrust(X509Certificate[] certs) throws WSSecurityException {
		LOGGER.debug("verifyTrust(X509Certificate[])");
		return false;
	}

	@Override
	public boolean verifyTrust(X509Certificate[] certs, boolean enableRevocation) throws WSSecurityException {
		LOGGER.debug("verifyTrust(X509Certificate[], boolean)");
		X509Certificate samlSigner = certs[0];
		LOGGER.debug("SAML signer: {}", samlSigner);
		// here we check the trust in the passive Identity Provider SAML signing
		// certificate
		boolean result = SAMLSTSTest.getSAMLSignerCertificate().equals(samlSigner);
		LOGGER.debug("verify trust result: {}", result);
		return result;
	}

	@Override
	public boolean verifyTrust(PublicKey publicKey) throws WSSecurityException {
		LOGGER.debug("verifyTrust(PublicKey)");
		return false;
	}
}
