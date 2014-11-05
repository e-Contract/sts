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

import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.security.auth.callback.CallbackHandler;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ClientCrypto implements Crypto {

	private static final Logger LOGGER = LoggerFactory
			.getLogger(ClientCrypto.class);

	private final PrivateKey privateKey;

	private final X509Certificate certificate;

	public ClientCrypto(PrivateKey privateKey, X509Certificate certificate) {
		this.privateKey = privateKey;
		this.certificate = certificate;
	}

	@Override
	public byte[] getBytesFromCertificates(X509Certificate[] certs)
			throws WSSecurityException {
		return null;
	}

	@Override
	public CertificateFactory getCertificateFactory()
			throws WSSecurityException {
		return null;
	}

	@Override
	public X509Certificate[] getCertificatesFromBytes(byte[] data)
			throws WSSecurityException {
		return null;
	}

	@Override
	public String getCryptoProvider() {
		return null;
	}

	@Override
	public String getDefaultX509Identifier() throws WSSecurityException {
		return null;
	}

	@Override
	public PrivateKey getPrivateKey(X509Certificate certificate,
			CallbackHandler callbackHandler) throws WSSecurityException {
		return null;
	}

	@Override
	public PrivateKey getPrivateKey(String identifier, String password)
			throws WSSecurityException {
		return this.privateKey;
	}

	@Override
	public byte[] getSKIBytesFromCert(X509Certificate cert)
			throws WSSecurityException {
		return null;
	}

	@Override
	public X509Certificate[] getX509Certificates(CryptoType cryptoType)
			throws WSSecurityException {
		X509Certificate[] certificates = new X509Certificate[] { this.certificate };
		return certificates;
	}

	@Override
	public String getX509Identifier(X509Certificate cert)
			throws WSSecurityException {
		LOGGER.debug("getX509Identifier");
		return null;
	}

	@Override
	public X509Certificate loadCertificate(InputStream in)
			throws WSSecurityException {
		return null;
	}

	@Override
	public void setCertificateFactory(String provider,
			CertificateFactory certFactory) {
	}

	@Override
	public void setCryptoProvider(String provider) {
	}

	@Override
	public void setDefaultX509Identifier(String identifier) {
	}

	@Override
	public boolean verifyTrust(X509Certificate[] certs)
			throws WSSecurityException {
		return false;
	}

	@Override
	public boolean verifyTrust(PublicKey publicKey) throws WSSecurityException {
		return false;
	}

	@Override
	public boolean verifyTrust(X509Certificate[] certs, boolean enableRevocation)
			throws WSSecurityException {
		return false;
	}
}
