/*
 * Copyright (c) 2017 VMware, Inc. All Rights Reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */
package com.vmware.o11n.plugin.crypto.model;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.springframework.beans.factory.annotation.Autowired;

import com.vmware.o11n.plugin.sdk.annotation.VsoMethod;
import com.vmware.o11n.plugin.sdk.annotation.VsoObject;
import com.vmware.o11n.plugin.sdk.annotation.VsoParam;
import com.vmware.o11n.plugin.sdk.spring.AbstractSpringPluginFactory;

import ch.dunes.vso.sdk.api.IPluginFactory;

@VsoObject(
create=false,
strict=true,
singleton=true,
description="Provides static methods to encrypt/decrypt data with different ciphers.")
public class CryptoEncryption {

	public static final String TYPE = "CryptoEncryption";

	@Autowired
	private CryptoEncryptionService service;

	public static CryptoEncryption createScriptingSingleton(IPluginFactory factory) {
		return ((AbstractSpringPluginFactory) factory).createScriptingObject(CryptoEncryption.class);
	}

	@VsoMethod(description="AES Encryption. Returns Base64 encoded encrypted data")
	public String aesEncrypt(
			@VsoParam(description="Base64 encoded data to encrypt")String dataB64,
			@VsoParam(description="Encryption secret Base64 encoded. For AES128 this should be 128 bits (16 bytes) long. For AES256 this should be 256 bits (32 bytes) long.")String secretB64,
			@VsoParam(description="Base64 encoded initialization vector. 16 bytes long")String ivB64) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		return service.aesEncrypt(dataB64, secretB64, ivB64);
	}

	@VsoMethod(description="AES Decryption. Returns Base64 encoded data")
	public String aesDecrypt(
			@VsoParam(description="Base64 encoded encrypted data to decrypt")String encryptedB64,
			@VsoParam(description="Encryption secret Base64 encoded. For AES128 this should be 128 bits (16 bytes) long. For AES256 this should be 256 bits (32 bytes) long.")String secretB64,
			@VsoParam(description="Base64 encoded initialization vector. 16 bytes long")String ivB64) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		return service.aesDecrypt(encryptedB64, secretB64, ivB64);
	}

	@VsoMethod(description="Returns 16 random bytes encoded as a Base64 string suitable for an AES Initialization Vector")
	public String generateRandomIv() {
		return service.generateRandomBytes(16);
	}

	@VsoMethod(description="Returns a number of random bytes encoded as a Base64 string")
	public String generateRandomBytes(@VsoParam(description="Number of random bytes",vsoType="Number") Integer numberOfBytes) {
		return service.generateRandomBytes(numberOfBytes);
	}
}
