/*
 * Copyright (c) 2017 VMware, Inc. All Rights Reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */
package com.vmware.o11n.plugin.crypto;


import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

import javax.naming.InvalidNameException;

import org.junit.Test;

import com.vmware.o11n.plugin.crypto.model.CryptoUtil;
import com.vmware.o11n.plugin.crypto.service.CryptoCertificateService;


public class CryptoCertificateServiceTest {
	CryptoCertificateService service = new CryptoCertificateService();

	@Test
	public void certificateFingerprintSha1() throws CertificateException {
		String thumb = service.getSha1Fingerprint(CryptoTestData.vcsa_01aCert);
		assertEquals("Certificate SHA1 Fingerprint", CryptoTestData.vcsa_01aCertSha1Thumb, thumb);
	}

	@Test
	public void certificateFingerprintSha256() throws CertificateException {
		String thumb = service.getSha256Fingerprint(CryptoTestData.vcsa_01aCert);
		assertEquals("Certificate SHA256 Fingerprint", CryptoTestData.vcsa_01aCertSha256Thumb, thumb);
	}

	@Test
	public void certificatePublicKey() throws CertificateException {
		Certificate cert = service.parseCertificate(CryptoTestData.vcsa_01aCert);
		String key = service.getPublicKeyPem(cert);
		assertEquals("cert public key", CryptoTestData.vcsa01aPublicKey, key);
	}

	@Test
	public void subjectAlternativeNames() throws CertificateException {
		Certificate cert = service.parseCertificate(CryptoTestData.vcsa_01aCert);
		List<String> san = service.getSubjectAlternativeNames((X509Certificate)cert);
		assertArrayEquals("cert subject alternative names", CryptoTestData.vcsa_01aSAN, san.toArray(new String[san.size()]));
	}

	@Test
	public void remoteCertVmware() throws KeyManagementException, NoSuchAlgorithmException, IOException, CertificateParsingException, InvalidNameException, InvalidKeySpecException {
		URL vmwareUrl = new URL(CryptoTestData.vmwareUrl);
		List<X509Certificate> certs = service.getCertHttps(vmwareUrl);
		assertEquals("VMware.com cert count", 2, certs.size());
		assertTrue("VMware.com cert SAN count greater than 0", 0 < service.getSubjectAlternativeNames(certs.get(0)).size());
		assertEquals("Intermediary cert should have empty SAN", 0, service.getSubjectAlternativeNames(certs.get(1)).size());
		assertEquals("VMware.com issued to CN", CryptoTestData.vmwareIssuedTo, service.parseDN(certs.get(0).getSubjectDN().getName()).get("CN"));
		assertTrue("vmware.com cert signed by intermediary", service.verifyCert(certs.get(0), certs.get(1).getPublicKey()));
		assertTrue("vmware.com cert signed by intermediary string key", service.verifyCert(certs.get(0), CryptoUtil.pemEncode(certs.get(1).getPublicKey())));
	}

	@Test
	public void remoteCertGithub() throws KeyManagementException, NoSuchAlgorithmException, IOException, CertificateParsingException, InvalidNameException, InvalidKeySpecException {
		URL githubUrl = new URL(CryptoTestData.githubUrl);
		List<X509Certificate> certs = service.getCertHttps(githubUrl);
		assertEquals("github.com cert count", 2, certs.size());
		assertTrue("github.com cert SAN count greater than 0", 0 < service.getSubjectAlternativeNames(certs.get(0)).size());
		assertEquals("Intermediary cert should have empty SAN", 0, service.getSubjectAlternativeNames(certs.get(1)).size());
		assertEquals("github.com issued to CN", CryptoTestData.githubIssuedTo, service.parseDN(certs.get(0).getSubjectDN().getName()).get("CN"));
		assertTrue("github.com cert signed by intermediary", service.verifyCert(certs.get(0), certs.get(1).getPublicKey()));
		assertTrue("github.com cert signed by intermediary string key", service.verifyCert(certs.get(0), CryptoUtil.pemEncode(certs.get(1).getPublicKey())));
	}
}