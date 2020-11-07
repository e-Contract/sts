/*
 * eID Security Token Service Project.
 * Copyright (C) 2019-2020 e-Contract.be BV.
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.apache.ws.security.WSSecurityException;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.joda.time.DateTime;

public class TestOnBehalfOfService implements OnBehalfOfService {

	private static final X509Certificate SAML_SIGNER_CERTIFICATE;

	private static final PrivateKey SAML_SIGNER_PRIVATE_KEY;

	static {
		KeyPairGenerator keyPairGenerator;
		try {
			keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		SAML_SIGNER_PRIVATE_KEY = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();
		try {
			SAML_SIGNER_CERTIFICATE = getCertificate(SAML_SIGNER_PRIVATE_KEY, publicKey);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private static X509Certificate getCertificate(PrivateKey privateKey, PublicKey publicKey) throws Exception {
		X500Name subjectName = new X500Name("CN=SAML STS Signer");
		X500Name issuerName = subjectName; // self-signed
		BigInteger serial = new BigInteger(128, new SecureRandom());
		SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(issuerName, serial,
				notBefore.toDate(), notAfter.toDate(), subjectName, publicKeyInfo);
		AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1withRSA");
		AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
		AsymmetricKeyParameter asymmetricKeyParameter = PrivateKeyFactory.createKey(privateKey.getEncoded());

		ContentSigner contentSigner = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(asymmetricKeyParameter);
		X509CertificateHolder x509CertificateHolder = x509v3CertificateBuilder.build(contentSigner);

		byte[] encodedCertificate = x509CertificateHolder.getEncoded();

		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		X509Certificate certificate = (X509Certificate) certificateFactory
				.generateCertificate(new ByteArrayInputStream(encodedCertificate));
		return certificate;
	}

	public static X509Certificate getSAMLSignerCertificate() {
		return SAML_SIGNER_CERTIFICATE;
	}

	@Override
	public String getIssuer() {
		return "https://issuer";
	}

	@Override
	public PrivateKey getPrivateKey() {
		return SAML_SIGNER_PRIVATE_KEY;
	}

	@Override
	public X509Certificate getCertificate() {
		return SAML_SIGNER_CERTIFICATE;
	}

	@Override
	public boolean verifyTrust(X509Certificate callerCertificate, X509Certificate certificate)
			throws WSSecurityException {
		assertNotNull(callerCertificate);
		assertEquals(OnBehalfOfTest.getCallerCertificate(), callerCertificate);
		boolean result = OnBehalfOfTest.getSAMLSignerCertificate().equals(certificate);
		return result;
	}

	@Override
	public long getLifetime(X509Certificate callerCertificate) {
		assertNotNull(callerCertificate);
		assertEquals(OnBehalfOfTest.getCallerCertificate(), callerCertificate);
		return 60 * 60 * 3;
	}

	@Override
	public long getMaxLifetime(X509Certificate callerCertificate) {
		assertNotNull(callerCertificate);
		assertEquals(OnBehalfOfTest.getCallerCertificate(), callerCertificate);
		return 60 * 60 * 10;
	}

	@Override
	public boolean isAddressInEndpoints(X509Certificate callerCertificate, String address) {
		assertEquals(OnBehalfOfTest.getCallerCertificate(), callerCertificate);
		assertNotNull(address);
		return true;
	}
}
