/*
 * Copyright (c) 2017 VMware, Inc. All Rights Reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */
package com.vmware.o11n.plugin.crypto;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import com.vmware.o11n.plugin.crypto.model.CryptoCertificate;

public class CryptoCertificateTest {

	private CryptoCertificate cert = new CryptoCertificate(CryptoTestData.vcsa_01aCert);

	@Test
	public void certificateFingerprintSha1() {
		String thumb = cert.getSha1Fingerprint();
		assertEquals("Certificate SHA1 Fingerprint", CryptoTestData.vcsa_01aCertSha1Thumb, thumb);
	}

	@Test
	public void certificateFingerprintSha256() {
		String thumb = cert.getSha256Fingerprint();
		assertEquals("Certificate SHA256 Fingerprint", CryptoTestData.vcsa_01aCertSha256Thumb, thumb);
	}

}
