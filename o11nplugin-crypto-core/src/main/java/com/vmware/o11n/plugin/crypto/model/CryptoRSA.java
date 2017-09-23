/*
 * Copyright (c) 2017 VMware, Inc. All Rights Reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */
package com.vmware.o11n.plugin.crypto.model;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
description="Provides static methods to encrypt / decrypt / sign data with RSA style encryption")
public class CryptoRSA {
	public static final String TYPE = "CryptoRSA";
	private final Logger log = LoggerFactory.getLogger(CryptoRSA.class);

	@Autowired
	private CryptoRSAService service;

	public static CryptoRSA createScriptingSingleton(IPluginFactory factory) {
		return ((AbstractSpringPluginFactory) factory).createScriptingObject(CryptoRSA.class);
	}

	@VsoMethod(description="Asymmetric RSA Encryption. Result is Base64 encoded")
	public String encrypt(@VsoParam(description="PEM encoded Public or Private Key")String key, @VsoParam(description="Base64 encoded data to encrypt")String dataB64) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		return service.encrypt(key, dataB64);
	}

	@VsoMethod(description = "Asymmetric RSA Decryption. Result is Base64 encoded")
	public String decrypt(@VsoParam(description="PEM encoded Private Key")String key, @VsoParam(description="Base64 encoded encrypted data")String encryptedB64) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		return service.decrypt(key, encryptedB64);
	}

	@VsoMethod(description = "Creates a RSA Signature")
	public String createSignature(@VsoParam(description="PEM encoded Private Key")String key, @VsoParam(description="Base64 encoded message to sign")String dataB64) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, IOException {
		return service.sign(key, dataB64);
	}

	@VsoMethod(description = "Verifies a RSA Signature")
	public boolean verifySignature(@VsoParam(description="PEM encoded Public or Private Key")String key, @VsoParam(description="Base64 encoded signed message")String dataB64, @VsoParam(description="Base64 encoded RSA signature to verify")String signatureB64) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, IOException {
		return service.verifySignature(key, dataB64, signatureB64);
	}
}
