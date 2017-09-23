/*
 * Copyright (c) 2017 VMware, Inc. All Rights Reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */
package com.vmware.o11n.plugin.crypto.model;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import net.oauth.signature.pem.PEMReader;
import net.oauth.signature.pem.PKCS1EncodedKeySpec;

@Component
public class CryptoRSAService {
	private final Logger log = LoggerFactory.getLogger(CryptoRSAService.class);

	private static final String CIPHER_TRANSFORMATION = "RSA/ECB/PKCS1Padding";
	private static final String SIGNATURE_ALGORITHM = "NONEwithRSA";
	private static final String KEYFACTORY_ALGORITHM = "RSA";

	/**
	 * RSA Encryption
	 *
	 * @param pemKey RSA Key (Public or Private, Public will be derived from Private)
	 * @param dataB64 Data encoded with Base64 to encrypt
	 * @return Encrypted data Base64 encoded
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public String encrypt(String pemKey, String dataB64) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		String encryptedB64 = null;
		PublicKey publicKey = null;

		Key key = null;
		try {
			key = getKey(pemKey);   //can be private or public
		} catch (IOException e) {
			//try to fix key:
			key = getKey(CryptoUtil.fixPemString(pemKey));
		}
		if (key instanceof RSAPublicKey) {
			publicKey = (RSAPublicKey)key;
		} else if (key instanceof RSAPrivateCrtKey) {
			RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) key;
			publicKey = getPublicFromPrivate(privateKey);
		} else {
			throw new IllegalArgumentException("Unknown key object type: "+key.getClass().getName());
		}

		Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		encryptedB64 = Base64.encodeBase64String(cipher.doFinal(Base64.decodeBase64(dataB64)));
		return encryptedB64;
	}

	/**
	 * RSA Decryption
	 *
	 * @param pemKey RSA Private Key
	 * @param encryptedB64 RSA Encrypted data encoded with Base64
	 * @return Original data Base64 Encoded
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public String decrypt(String pemKey, String encryptedB64) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		String dataB64 = null;
		PrivateKey privateKey = null;
		Key key = null;
		try {
			key = getKey(pemKey);
		} catch (IOException e) {
			//try to fix key:
			key = getKey(CryptoUtil.fixPemString(pemKey));
		}
		if (key instanceof PrivateKey) {
			privateKey = (PrivateKey) key;
		} else {
			throw new IllegalArgumentException("Invalid key object type: "+key.getClass().getName());
		}

		Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		dataB64 = Base64.encodeBase64String(cipher.doFinal(Base64.decodeBase64(encryptedB64)));
		return dataB64;
	}

	/**
	 * Creates an RSA Signature
	 *
	 * @param pemKey RSA Private Key
	 * @param dataB64 Base64 encoded data to sign
	 * @return Base64 encoded signature
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws IOException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 */
	public String sign(String pemKey, String dataB64) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException {
		String signatureB64 = null;
		PrivateKey privateKey = null;

		Key key = null;
		try {
			key = getKey(pemKey);
		} catch (IOException e) {
			//try to fix key:
			key = getKey(CryptoUtil.fixPemString(pemKey));
		}
		if (key instanceof PrivateKey) {
			privateKey = (PrivateKey) key;
		} else {
			throw new IllegalArgumentException("Invalid key object type: "+key.getClass().getName());
		}

		Signature signer = Signature.getInstance(SIGNATURE_ALGORITHM);
		signer.initSign(privateKey);
		signer.update(Base64.decodeBase64(dataB64));
		byte[] sigBytes = signer.sign();
		signatureB64 = Base64.encodeBase64String(sigBytes);

		return signatureB64;
	}

	/**
	 * Verify a RSA Signature with a RSA Public Key
	 *
	 * @param pemKey RSA Key (Public or Private, Public will be derived from Private)
	 * @param dataB64 Base64 encoded data the signature was created from
	 * @param signatureB64 Base64 Encoded RSA Signature to verify
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws IOException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 */
	public boolean verifySignature(String pemKey, String dataB64, String signatureB64) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException {
		boolean valid = false;
		PublicKey publicKey = null;

		Key key = null;
		try {
			key = getKey(pemKey);   //can be private or public
		} catch (IOException e) {
			//try to fix key:
			key = getKey(CryptoUtil.fixPemString(pemKey));
		}

		if (key instanceof RSAPublicKey) {
			publicKey = (RSAPublicKey)key;
		} else if (key instanceof RSAPrivateCrtKey) {
			RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) key;
			publicKey = getPublicFromPrivate(privateKey);
		} else {
			throw new IllegalArgumentException("Unknown key object type: "+key.getClass().getName());
		}

		Signature signer = Signature.getInstance(SIGNATURE_ALGORITHM);
		signer.initVerify(publicKey);
		signer.update(Base64.decodeBase64(dataB64));
		valid = signer.verify(Base64.decodeBase64(signatureB64));

		return valid;
	}


	/**
	 *
	 * @param pem
	 * @return
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	private Key getKey(String pem) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		ByteArrayInputStream stream = new ByteArrayInputStream(pem.getBytes());
		PEMReader reader = new PEMReader(stream);
		byte[] derBytes = reader.getDerBytes();

		KeySpec keySpec;

		if (PEMReader.PRIVATE_PKCS1_MARKER.equals(reader.getBeginMarker())) {
			keySpec = (new PKCS1EncodedKeySpec(derBytes)).getKeySpec();
			return getPrivateKey(keySpec);
		} else if (PEMReader.PRIVATE_PKCS8_MARKER.equals(reader.getBeginMarker())) {
			keySpec = new java.security.spec.PKCS8EncodedKeySpec(derBytes);
			return getPrivateKey(keySpec);
		} else if (PEMReader.PUBLIC_X509_MARKER.equals(reader.getBeginMarker())) {
			keySpec = new java.security.spec.X509EncodedKeySpec(derBytes);
			return getPublicKey(keySpec);
		} else {
			throw new IOException("Invalid PEM file: Unknown marker for private or public key " + reader.getBeginMarker());
		}
	}

	/**
	 * Generate a RSA Public Key from a KeySpec
	 *
	 * @param keySpec
	 * @return RSA Public Key
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	private PublicKey getPublicKey(KeySpec keySpec) throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyFactory fac = KeyFactory.getInstance(KEYFACTORY_ALGORITHM);
		return fac.generatePublic(keySpec);
	}

	/**
	 * Generate a RSA Private Key from a KeySpec
	 *
	 * @param keySpec
	 * @return RSA Private Key
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	private PrivateKey getPrivateKey(KeySpec keySpec) throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyFactory fac = KeyFactory.getInstance(KEYFACTORY_ALGORITHM);
		return fac.generatePrivate(keySpec);
	}

	/**
	 * Compute the RSA Public Key from an RSA Private Key
	 *
	 * @param privateKey RSA Private Key
	 * @return RSA Public Key
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	private RSAPublicKey getPublicFromPrivate(RSAPrivateCrtKey privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
		RSAPublicKeySpec spec = new RSAPublicKeySpec(privateKey.getModulus(), privateKey.getPublicExponent());
		return (RSAPublicKey)getPublicKey(spec);
	}


}
