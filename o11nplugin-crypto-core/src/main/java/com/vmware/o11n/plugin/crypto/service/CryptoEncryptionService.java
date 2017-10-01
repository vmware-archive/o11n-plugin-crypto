/*
 * Copyright (c) 2017 VMware, Inc. All Rights Reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */
package com.vmware.o11n.plugin.crypto.service;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class CryptoEncryptionService {

	private final Logger log = LoggerFactory.getLogger(CryptoEncryptionService.class);

	private static final String AES_CIPHER = "AES/CBC/PKCS5Padding";
	private static final String DESEDE_CIPHER = "DESede/CBC/PKCS5Padding"; //3DES

	/**
	 * AES Encryption CBC Mode with PKCS5 Padding
	 *
	 * @param dataB64 Data to encrypt Base64 encoded
	 * @param secretB64 Encryption secret Base64 encoded. For AES128 this should be 128 bits (16 bytes) long. For AES256 this should be 256 bits (32 bytes) long.
	 * @param ivB64 Initialization Vector Base64 encoded. 16 bytes long
	 * @return Encrypted data Base64 Encoded
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IOException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public String aesEncrypt(String dataB64, String secretB64, String ivB64) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		String encryptedB64 = null;

		final byte[] dataBytes = Base64.decodeBase64(dataB64);
		final byte[] secretBytes = Base64.decodeBase64(secretB64);
		final byte[] ivBytes = Base64.decodeBase64(ivB64);
		final Cipher cipher = Cipher.getInstance(AES_CIPHER);

		cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(secretBytes, "AES"), new IvParameterSpec(ivBytes, 0, cipher.getBlockSize()));

		encryptedB64 = Base64.encodeBase64String(cipher.doFinal(dataBytes));
		return encryptedB64;
	}
	/**
	 * AES Decryption CBC Mode with PKCS5 Padding
	 *
	 * @param encryptedB64 Encrypted Data Base64 encoded.
	 * @param secretB64 Encryption secret Base64 encoded. For AES128 this should be 128 bits (16 bytes) long. For AES256 this should be 256 bits (32 bytes) long.
	 * @param ivB64 Initialization Vector Base64 encoded. 16 bytes long
	 * @return Original data Base64 encoded.
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IOException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public String aesDecrypt(String encryptedB64, String secretB64, String ivB64) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		String dataB64 = null;

		final byte[] encryptedBytes = Base64.decodeBase64(encryptedB64);
		final byte[] secretBytes = Base64.decodeBase64(secretB64);
		final byte[] ivBytes = Base64.decodeBase64(ivB64);
		final Cipher cipher = Cipher.getInstance(AES_CIPHER);

		cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(secretBytes, "AES"), new IvParameterSpec(ivBytes, 0, cipher.getBlockSize()));

		dataB64 = Base64.encodeBase64String(cipher.doFinal(encryptedBytes));
		return dataB64;
	}

	/**
	 * TripleDES (EDE) Encryption CBC Mode with PKCS5 padding
	 *
	 * @param dataB64 Data to encrypt Base64 encoded.
	 * @param secretB64 Encryption secret Base64 encoded. Secret must be at least 24 bytes. Only the first 24 bytes will be used.
	 * @param ivB64 Initialization Vector Base64 encoded. Only first 8 bytes will be used.
	 * @return Encrypted data Base64 encoded.
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IOException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public String tripleDesEncrypt(String dataB64, String secretB64, String ivB64) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		String encryptedB64 = null;

		final byte[] dataBytes = Base64.decodeBase64(dataB64);
		final byte[] secretBytes = Base64.decodeBase64(secretB64);
		final byte[] ivBytes = Base64.decodeBase64(ivB64);
		final Cipher cipher = Cipher.getInstance(DESEDE_CIPHER);

		DESedeKeySpec keySpec = new DESedeKeySpec(secretBytes);
		cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keySpec.getKey(), "DESede"), new IvParameterSpec(ivBytes, 0, cipher.getBlockSize()));

		encryptedB64 = Base64.encodeBase64String(cipher.doFinal(dataBytes));
		return encryptedB64;
	}
	/**
	 * TripleDES (EDE) Decryption CBC Mode with PKCS5 padding
	 *
	 * @param encryptedB64 Encrypted data Base64 encoded
	 * @param secretB64 Encryption secret Base64 encoded. Secret must be at least 24 bytes. Only the first 24 bytes will be used.
	 * @param ivB64 Initialization Vector Base64 encoded. Only first 8 bytes will be used.
	 * @return Original data Base64 encoded.
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IOException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public String tripleDesDecrypt(String encryptedB64, String secretB64, String ivB64) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		String dataB64 = null;

		final byte[] encryptedBytes = Base64.decodeBase64(encryptedB64);
		final byte[] secretBytes = Base64.decodeBase64(secretB64);
		final byte[] ivBytes = Base64.decodeBase64(ivB64);
		final Cipher cipher = Cipher.getInstance(DESEDE_CIPHER);

		DESedeKeySpec keySpec = new DESedeKeySpec(secretBytes);
		cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keySpec.getKey(), "DESede"), new IvParameterSpec(ivBytes, 0, cipher.getBlockSize()));

		dataB64 = Base64.encodeBase64String(cipher.doFinal(encryptedBytes));
		return dataB64;
	}

	/**
	 * Random data generator
	 *
	 * Creates a new SecureRandom instance for each all.  Each instance is self seeding.
	 *
	 * @param numberOfBytes Number of Random Bytes to return
	 * @return Random bytes Base64 Encoded
	 */
	public String generateRandomBytes(Integer numberOfBytes) {
		byte[] ivBytes = new byte[numberOfBytes];
		final SecureRandom rng = new SecureRandom();
		rng.nextBytes(ivBytes);
		return Base64.encodeBase64String(ivBytes);
	}
}
