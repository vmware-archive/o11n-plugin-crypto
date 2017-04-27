/*
 * Copyright (c) 2017 VMware, Inc. All Rights Reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */
package com.vmware.o11n.plugin.crypto;

import static org.junit.Assert.assertEquals;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.binary.Base64;
import org.junit.Test;

import com.vmware.o11n.plugin.crypto.model.CryptoDigestService;
import com.vmware.o11n.plugin.crypto.model.CryptoEncodingService;
import com.vmware.o11n.plugin.crypto.model.CryptoEncryptionService;

public class CryptoEncryptionServiceTest {

	CryptoEncryptionService service = new CryptoEncryptionService();
	CryptoEncodingService encodingService = new CryptoEncodingService();
	CryptoDigestService digestService = new CryptoDigestService();
	private final String staticString = "Hello World!!";
	private final String staticSecret = "VMware1!";

	/**
	 *
	 *
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	@Test
	public void aesTestStaticAES128() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		String ivB64 = service.generateRandomBytes(16);
		String dataB64 = encodingService.base64Encode(staticString);
		String secretB64 = digestService.md5Base64(encodingService.base64Encode(staticSecret));

		byte[] secretBytes = Base64.decodeBase64(secretB64);
		assertEquals("secretLength", 16, secretBytes.length);

		String encryptedB64 = service.aesEncrypt(dataB64, secretB64, ivB64);
		String decryptedB64 = service.aesDecrypt(encryptedB64, secretB64, ivB64);
		String decrypted = encodingService.base64Decode(decryptedB64);

		assertEquals("AES", staticString, decrypted);
	}

	/**
	 * Requires unlimited strength JRE Policy files which are part of vRO
	 *
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	@Test
	public void aesTestStaticAES256() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		String ivB64 = service.generateRandomBytes(16);
		String dataB64 = encodingService.base64Encode(staticString);
		String secretB64 = digestService.sha256Base64(encodingService.base64Encode(staticSecret));

		byte[] secretBytes = Base64.decodeBase64(secretB64);
		assertEquals("secretLength", 32, secretBytes.length);

		String encryptedB64 = service.aesEncrypt(dataB64, secretB64, ivB64);
		String decryptedB64 = service.aesDecrypt(encryptedB64, secretB64, ivB64);
		String decrypted = encodingService.base64Decode(decryptedB64);

		assertEquals("AES256 static ", staticString, decrypted);
	}

	@Test
	public void aesTestRandomAES128() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		String ivB64 = service.generateRandomBytes(16);
		String dataB64 = service.generateRandomBytes(2343);
		String secretB64 = service.generateRandomBytes(16);

		String encryptedB64 = service.aesEncrypt(dataB64, secretB64, ivB64);
		String decryptedB64 = service.aesDecrypt(encryptedB64, secretB64, ivB64);

		assertEquals("AES128 Random", dataB64, decryptedB64);
	}

	@Test
	public void aesTestRandomAES256() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		String ivB64 = service.generateRandomBytes(16);
		String dataB64 = service.generateRandomBytes(2343);
		String secretB64 = service.generateRandomBytes(32);

		String encryptedB64 = service.aesEncrypt(dataB64, secretB64, ivB64);
		String decryptedB64 = service.aesDecrypt(encryptedB64, secretB64, ivB64);

		assertEquals("AES256 Random", dataB64, decryptedB64);
	}

	@Test
	public void testRandom3DES192() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		String ivB64 = service.generateRandomBytes(16);
		String dataB64 = service.generateRandomBytes(2343);
		String secretB64 = service.generateRandomBytes(24);

		String encryptedB64 = service.tripleDesEncrypt(dataB64, secretB64, ivB64);
		String decryptedB64 = service.tripleDesDecrypt(encryptedB64, secretB64, ivB64);

		assertEquals("3DES Random 192key", dataB64, decryptedB64);
	}

	@Test
	public void testRandomZero() {
		String result = service.generateRandomBytes(0);
		assertEquals("RandomZero", "", result);
	}

	@Test (expected=NegativeArraySizeException.class)
	public void testRandomNegative() {
		service.generateRandomBytes(-4);
	}

	@Test (expected=NullPointerException.class)
	public void testRandomNull() {
		service.generateRandomBytes(null);
	}
}
