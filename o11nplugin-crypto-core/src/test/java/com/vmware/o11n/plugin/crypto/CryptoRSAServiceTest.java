/*
 * Copyright (c) 2017 VMware, Inc. All Rights Reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */
package com.vmware.o11n.plugin.crypto;
import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.junit.Test;

import com.vmware.o11n.plugin.crypto.service.CryptoEncryptionService;
import com.vmware.o11n.plugin.crypto.service.CryptoRSAService;

public class CryptoRSAServiceTest {

	CryptoRSAService service = new CryptoRSAService();
	CryptoEncryptionService encryptionService = new CryptoEncryptionService();

	@Test
	public void staticRSAEncryptTest() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {
		String encryptedB64 = service.encrypt(CryptoTestData.publicPem, CryptoTestData.staticStringB64);
		String decryptedB64 = service.decrypt(CryptoTestData.privatePem, encryptedB64);
		assertEquals("RSA Static", CryptoTestData.staticStringB64, decryptedB64);
	}

	@Test (expected=IllegalArgumentException.class)
	public void wrongKeyRSAEncrypt() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {
		String encryptedB64 = service.encrypt(CryptoTestData.publicPem, CryptoTestData.staticStringB64);
		String decryptedB64 = service.decrypt(CryptoTestData.publicPem, encryptedB64); //should fail
		assertEquals("RSA Static", CryptoTestData.staticStringB64, decryptedB64);
	}

	@Test
	public void randomRSAEncryptTest() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {
		final String dataB64 = encryptionService.generateRandomBytes(245);
		String encryptedB64 = service.encrypt(CryptoTestData.publicPem, dataB64);
		String decryptedB64 = service.decrypt(CryptoTestData.privatePem, encryptedB64);
		assertEquals("RSA Dynamic", dataB64, decryptedB64);
	}

	@Test (expected=IllegalBlockSizeException.class)
	public void randomRSAEncryptTestExcessiveData() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {
		final String dataB64 = encryptionService.generateRandomBytes(246);
		String encryptedB64 = service.encrypt(CryptoTestData.publicPem, dataB64);  //should fail
		String decryptedB64 = service.decrypt(CryptoTestData.privatePem, encryptedB64);
		assertEquals("RSA Dynamic", dataB64, decryptedB64);
	}

	@Test
	public void randomRSAEncryptPrivatePrivateTest() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {
		final String dataB64 = encryptionService.generateRandomBytes(245);
		String encryptedB64 = service.encrypt(CryptoTestData.privatePem, dataB64);
		String decryptedB64 = service.decrypt(CryptoTestData.privatePem, encryptedB64);
		assertEquals("RSA Dynamic", dataB64, decryptedB64);
	}

	@Test
	public void signAndVerify() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, IOException {
		String sigB64 = service.sign(CryptoTestData.privatePem, CryptoTestData.staticStringB64);
		boolean valid = service.verifySignature(CryptoTestData.publicPem, CryptoTestData.staticStringB64, sigB64);
		assertEquals("Sign and Verify", true, valid);
	}

	@Test
	public void signAndVerifyOneLine() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, IOException {
		String sigB64 = service.sign(CryptoTestData.privatePemOneLine, CryptoTestData.staticStringB64);
		boolean valid = service.verifySignature(CryptoTestData.publicPemOneLine, CryptoTestData.staticStringB64, sigB64);
		assertEquals("Sign and Verify One Line PEMs", true, valid);
	}

	@Test
	public void signAndVerifyPrivatePrivate() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, IOException {
		String sigB64 = service.sign(CryptoTestData.privatePem, CryptoTestData.staticStringB64);
		boolean valid = service.verifySignature(CryptoTestData.privatePem, CryptoTestData.staticStringB64, sigB64);
		assertEquals("Sign and Verify Private Private", true, valid);
	}

	@Test (expected=SignatureException.class)
	public void signAndVerifyRandomLarge() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, IOException {
		final String dataB64 = encryptionService.generateRandomBytes(2453);
		String sigB64 = service.sign(CryptoTestData.privatePem, dataB64); //should fail
		boolean valid = service.verifySignature(CryptoTestData.publicPem, dataB64, sigB64);
		assertEquals("Sign and Verify Large", true, valid);
	}

	@Test
	public void signAndVerifyRandom() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, IOException {
		final String dataB64 = encryptionService.generateRandomBytes(245);
		String sigB64 = service.sign(CryptoTestData.privatePem, dataB64);
		boolean valid = service.verifySignature(CryptoTestData.publicPem, dataB64, sigB64);
		assertEquals("Sign and Verify Random", true, valid);
	}

	@Test
	public void rsaRandomEncryptOneLinePem() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {
		final String dataB64 = encryptionService.generateRandomBytes(245);
		String encryptedB64 = service.encrypt(CryptoTestData.publicPemOneLine, dataB64);
		String decryptedB64 = service.decrypt(CryptoTestData.privatePemOneLine, encryptedB64);
		assertEquals("RSA Dynamic One line PEMs", dataB64, decryptedB64);
	}

}