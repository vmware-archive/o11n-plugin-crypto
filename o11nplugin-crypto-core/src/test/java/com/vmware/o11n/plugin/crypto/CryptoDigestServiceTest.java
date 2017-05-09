/*
 * Copyright (c) 2017 VMware, Inc. All Rights Reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */
package com.vmware.o11n.plugin.crypto;

import static org.junit.Assert.assertEquals;

import java.io.UnsupportedEncodingException;

import org.apache.commons.codec.DecoderException;
import org.junit.Test;

import com.vmware.o11n.plugin.crypto.model.CryptoDigestService;
import com.vmware.o11n.plugin.crypto.model.CryptoEncodingService;

public class CryptoDigestServiceTest {

	CryptoDigestService service = new CryptoDigestService();
	CryptoEncodingService encodingService = new CryptoEncodingService();

	private final String dataToDigest = "SGVsbG8gV29ybGQhIQ=="; // "Hello World!!" base64 encoded

	//hmacSha1 sample data from AWS docs
	private final String stringToSign = "GET\n\n\nTue, 27 Mar 2007 19:36:42 +0000\n/johnsmith/photos/puppy.jpg";
	private final String sampleKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
	private final String expectedHmacSha1SigB64 = "bWq2s1WEIj+Ydj0vQ697zp+IXMU=";

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


	@Test
	public void hmacSha1AwsSample() throws UnsupportedEncodingException {
		final String keyB64 = encodingService.base64Encode(sampleKey);
		final String toSignB64 = encodingService.base64Encode(stringToSign);

		final String sigB64 = service.hmacSha1(keyB64, toSignB64);

		assertEquals("hmacSha1 AWS Sample", expectedHmacSha1SigB64, sigB64);
	}

	@Test
	public void hmacMd5() throws UnsupportedEncodingException, DecoderException {
		//test example data from https://en.wikipedia.org/wiki/Hash-based_message_authentication_code
		final String sigB64 = service.hmacMd5(encodingService.base64Encode("key"), encodingService.base64Encode("The quick brown fox jumps over the lazy dog"));
		assertEquals("hmacMd5", encodingService.hexToBase64("80070713463e7749b90c2dc24911e275"),sigB64);
	}

	@Test
	public void hmacSha1() throws DecoderException, UnsupportedEncodingException {
		//test example data from https://en.wikipedia.org/wiki/Hash-based_message_authentication_code
		final String sigB64 = service.hmacSha1(encodingService.base64Encode("key"), encodingService.base64Encode("The quick brown fox jumps over the lazy dog"));
		assertEquals("hmacSha1", encodingService.hexToBase64("de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"),sigB64);
	}

	@Test
	public void hmacSha256() throws UnsupportedEncodingException, DecoderException {
		//test example data from https://en.wikipedia.org/wiki/Hash-based_message_authentication_code
		final String sigB64 = service.hmacSha256(encodingService.base64Encode("key"), encodingService.base64Encode("The quick brown fox jumps over the lazy dog"));
		assertEquals("hmacSha256", encodingService.hexToBase64("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"),sigB64);
	}
}
