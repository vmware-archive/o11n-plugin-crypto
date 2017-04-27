/*
 * Copyright (c) 2017 VMware, Inc. All Rights Reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */
package com.vmware.o11n.plugin.crypto;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import com.vmware.o11n.plugin.crypto.model.CryptoDigestService;

public class CryptoDigestServiceTest {

	CryptoDigestService service = new CryptoDigestService();

	private final String dataToDigest = "SGVsbG8gV29ybGQhIQ=="; // "Hello World!!" base64 encoded

	@Test
	public void md5Base64() {
		final String expectedResult = "y/QTR7sZePbzIIeyzwHjUQ==";
		assertEquals("MD5Sum", expectedResult, service.md5Base64(dataToDigest));
	}

	@Test
	public void sha1Base64() {
		final String expectedResult = "pqfIFYs01VSVSkySGxRPgtddtoM=";
		assertEquals("SHA1", expectedResult, service.sha1Base64(dataToDigest));
	}
	@Test
	public void sha256Base64() {
		final String expectedResult = "CWwKcsMfmi1lEm2OikAaKrLy4h0KKCpv/mZCu+9l/9k=";
		assertEquals("SHA256", expectedResult, service.sha256Base64(dataToDigest));
	}
	@Test
	public void sha384Base64() {
		final String expectedResult = "3GmJaU4n2IldLCBoqu22RM0gLwvZA/tUNvYhwqrt7Jk1k0aQSy59ndKRWUFCY3GP";
		assertEquals("SHA384", expectedResult, service.sha384Base64(dataToDigest));
	}
	@Test
	public void sha512Base64() {
		final String expectedResult = "ZKaYjsDsrL30Ds9QTnC5pfYXSomSyFbH7iLh4L4DqIkEEpBLnRekZ9A1Wf5XPDJCcWFdvPGR5M/CWbWgGju4JA==";
		assertEquals("SHA512", expectedResult, service.sha512Base64(dataToDigest));
	}
}
