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
package test.integ.be.e_contract.sts;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509KeyManager;

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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MyKeyManager implements X509KeyManager {

	private static final Logger LOGGER = LoggerFactory.getLogger(MyKeyManager.class);

	private final PrivateKey serverPrivateKey;

	private final X509Certificate serverCertificate;

	public MyKeyManager() throws NoSuchAlgorithmException, Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		this.serverPrivateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();
		this.serverCertificate = getCertificate(this.serverPrivateKey, publicKey);
	}

	@Override
	public String[] getClientAliases(String string, Principal[] prncpls) {
		LOGGER.debug("getClientAliases");
		throw new UnsupportedOperationException("getClientAliases");
	}

	@Override
	public String chooseClientAlias(String[] strings, Principal[] prncpls, Socket socket) {
		LOGGER.debug("chooseClientAlias");
		throw new UnsupportedOperationException("chooseClientAlias");
	}

	@Override
	public String[] getServerAliases(String string, Principal[] prncpls) {
		LOGGER.debug("getServerAliases");
		throw new UnsupportedOperationException("getServerAliases");
	}

	@Override
	public String chooseServerAlias(String string, Principal[] prncpls, Socket socket) {
		LOGGER.debug("chooseServerAlias");
		throw new UnsupportedOperationException("chooseServerAlias");
	}

	@Override
	public X509Certificate[] getCertificateChain(String alias) {
		LOGGER.debug("getCertificateChain: {}", alias);
		return new X509Certificate[] { this.serverCertificate };
	}

	@Override
	public PrivateKey getPrivateKey(String alias) {
		LOGGER.debug("getPrivateKey: {}", alias);
		return this.serverPrivateKey;
	}

	private static X509Certificate getCertificate(PrivateKey privateKey, PublicKey publicKey) throws Exception {
		X500Name subjectName = new X500Name("CN=localhost");
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
}
