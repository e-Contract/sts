/*
 * eID Security Token Service Project.
 * Copyright (C) 2014-2019 e-Contract.be BVBA.
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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

import javax.security.auth.callback.CallbackHandler;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OnBehalfOfCrypto implements Crypto {

	private static final Logger LOGGER = LoggerFactory.getLogger(OnBehalfOfCrypto.class);

	private final PrivateKey privateKey;

	private final List<X509Certificate> certificates;

	public OnBehalfOfCrypto(PrivateKey privateKey, List<X509Certificate> certificates) {
		this.privateKey = privateKey;
		this.certificates = certificates;
		LOGGER.debug("constructor");
	}

	public OnBehalfOfCrypto(PrivateKey privateKey, X509Certificate certificate) {
		this.privateKey = privateKey;
		this.certificates = new LinkedList<>();
		this.certificates.add(certificate);
	}

	@Override
	public byte[] getBytesFromCertificates(X509Certificate[] certs) throws WSSecurityException {
		LOGGER.debug("getBytesFromCertificates");
		ByteArrayOutputStream output = new ByteArrayOutputStream();
		for (X509Certificate cert : certs) {
			try {
				output.write(cert.getEncoded());
			} catch (CertificateEncodingException | IOException e) {
				throw new RuntimeException(e);
			}
		}
		return output.toByteArray();
	}

	@Override
	public CertificateFactory getCertificateFactory() throws WSSecurityException {
		LOGGER.debug("getCertificateFactory");
		return null;
	}

	@Override
	public X509Certificate[] getCertificatesFromBytes(byte[] data) throws WSSecurityException {
		LOGGER.debug("getCertificatesFromBytes");
		return null;
	}

	@Override
	public String getCryptoProvider() {
		LOGGER.debug("getCryptoProvider");
		return null;
	}

	@Override
	public String getDefaultX509Identifier() throws WSSecurityException {
		LOGGER.debug("getDefaultX509Identifier");
		return "client";
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
		return this.privateKey;
	}

	@Override
	public byte[] getSKIBytesFromCert(X509Certificate cert) throws WSSecurityException {
		LOGGER.debug("getSKIBytesFromCert");
		return null;
	}

	@Override
	public X509Certificate[] getX509Certificates(CryptoType cryptoType) throws WSSecurityException {
		LOGGER.debug("getX509Certificates: {}", cryptoType);
		return this.certificates.toArray(new X509Certificate[this.certificates.size()]);
	}

	@Override
	public String getX509Identifier(X509Certificate cert) throws WSSecurityException {
		LOGGER.debug("getX509Identifier");
		return null;
	}

	@Override
	public X509Certificate loadCertificate(InputStream in) throws WSSecurityException {
		LOGGER.debug("loadCertificate");
		return null;
	}

	@Override
	public void setCertificateFactory(String provider, CertificateFactory certFactory) {
		LOGGER.debug("setCertificateFactory");
	}

	@Override
	public void setCryptoProvider(String provider) {
		LOGGER.debug("setCryptoProvider");
	}

	@Override
	public void setDefaultX509Identifier(String identifier) {
		LOGGER.debug("setDefaultX509Identifier");
	}

	@Override
	public boolean verifyTrust(X509Certificate[] certs) throws WSSecurityException {
		LOGGER.debug("verifyTrust(X509Certificate[])");
		return false;
	}

	@Override
	public boolean verifyTrust(PublicKey publicKey) throws WSSecurityException {
		LOGGER.debug("verifyTrust(PublicKey)");
		return false;
	}

	@Override
	public boolean verifyTrust(X509Certificate[] certs, boolean enableRevocation) throws WSSecurityException {
		LOGGER.debug("verifyTrust(X509Certificate[], boolean)");
		// the OnBehalfOf SAML signing certificate is verified here
		X509Certificate samlSigner = certs[0];
		boolean result = OnBehalfOfTest.getSAMLSignerCertificate().equals(samlSigner);
		LOGGER.debug("result: {}", result);
		return result;
	}
}
