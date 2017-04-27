/*
 * Copyright (c) 2017 VMware, Inc. All Rights Reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */
package com.vmware.o11n.plugin.crypto.model;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.springframework.stereotype.Component;

@Component
public class CryptoEncryptionService {

	private static final String AES_CIPHER = "AES/CBC/PKCS5Padding";
	private static final String DESEDE_CIPHER = "DESede/CBC/PKCS5Padding"; //3DES

	/**
	 *
	 * @param dataB64
	 * @param secretB64
	 * @param ivB64
	 * @return
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
	 *
	 * @param encryptedB64
	 * @param secretB64
	 * @param ivB64
	 * @return
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
	 *
	 * @param dataB64
	 * @param secretB64
	 * @param ivB64
	 * @return
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

		cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(secretBytes, "DESede"), new IvParameterSpec(ivBytes, 0, cipher.getBlockSize()));

		encryptedB64 = Base64.encodeBase64String(cipher.doFinal(dataBytes));
		return encryptedB64;
	}
	/**
	 *
	 * @param encryptedB64
	 * @param secretB64
	 * @param ivB64
	 * @return
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

		cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(secretBytes, "DESede"), new IvParameterSpec(ivBytes, 0, cipher.getBlockSize()));

		dataB64 = Base64.encodeBase64String(cipher.doFinal(encryptedBytes));
		return dataB64;
	}

	/**
	 *
	 * @return
	 */
	public String generateRandomBytes(Integer numberOfBytes) {
		byte[] ivBytes = new byte[numberOfBytes];
		final SecureRandom rng = new SecureRandom();
		rng.nextBytes(ivBytes);
		return Base64.encodeBase64String(ivBytes);
	}
}
