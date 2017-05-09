/*
 * Copyright (c) 2017 VMware, Inc. All Rights Reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */
package com.vmware.o11n.plugin.crypto.model;

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
description="Provides methods to hash data with different digests")

public class CryptoDigest {
	public static final String TYPE = "CryptoDigest";

	@Autowired
	private CryptoDigestService service;

	public static CryptoDigest createScriptingSingleton(IPluginFactory factory) {
		return ((AbstractSpringPluginFactory) factory).createScriptingObject(CryptoDigest.class);
	}

	@VsoMethod(description = "Returns a Base64 encoded 128 bit MD5 hash")
	public String md5Base64(@VsoParam(description="Base64 encoded data to hash with MD5") String dataB64) {
		return service.md5Base64(dataB64);
	}

	@VsoMethod(description = "Returns a Base64 encoded 128 bit MD5 hash")
	public String md5(@VsoParam(description="Plain String to hash with MD5") String data) {
		return service.md5(data);
	}

	@VsoMethod(description = "Returns a Base64 encoded 160 bit SHA-1 hash")
	public String sha1Base64(@VsoParam(description="Base64 encoded data to hash with SHA1") String dataB64) {
		return service.sha1Base64(dataB64);
	}

	@VsoMethod(description = "Returns a Base64 encoded 160 bit SHA-1 hash")
	public String sha1(@VsoParam(description="Plain String to hash with SHA1") String data) {
		return service.sha1(data);
	}

	@VsoMethod(description = "Returns a Base64 encoded 256 bit SHA256 hash")
	public String sha256Base64(@VsoParam(description="Base64 encoded data to hash with SHA256") String dataB64) {
		return service.sha256Base64(dataB64);
	}

	@VsoMethod(description = "Returns a Base64 encoded 256 bit SHA256 hash")
	public String sha256(@VsoParam(description="Plain String to hash with SHA256") String data) {
		return service.sha256(data);
	}

	@VsoMethod(description = "Returns a Base64 encoded 384 bit SHA384 hash")
	public String sha384Base64(@VsoParam(description="Base64 encoded data to hash with SHA384") String dataB64) {
		return service.sha384Base64(dataB64);
	}

	@VsoMethod(description = "Returns a Base64 encoded 384 bit SHA384 hash")
	public String sha384(@VsoParam(description="Plain String to hash with SHA384") String data) {
		return service.sha384(data);
	}

	@VsoMethod(description = "Returns a Base64 encoded 512 bit SHA512 hash")
	public String sha512Base64(@VsoParam(description="Base64 encoded data to hash with SHA512") String dataB64) {
		return service.sha512Base64(dataB64);
	}

	@VsoMethod(description = "Returns a Base64 encoded 512 bit SHA512 hash")
	public String sha512(@VsoParam(description="Plain String to hash with SHA512") String data) {
		return service.sha512(data);
	}

	@VsoMethod(description = "Returns HmacMD5 MAC for the given key and data Base64 encoded")
	public String hmacMd5(@VsoParam(description="Secret Key Base64 encoded") String keyB64,
							@VsoParam(description="Data to sign Base64 encoded") String dataB64) {
		return service.hmacMd5(keyB64, dataB64);
	}

	@VsoMethod(description = "Returns HmacSHA1 MAC for the given key and data Base64 encoded")
	public String hmacSha1(@VsoParam(description="Secret Key Base64 encoded") String keyB64,
							@VsoParam(description="Data to sign Base64 encoded") String dataB64) {
		return service.hmacSha1(keyB64, dataB64);
	}
	@VsoMethod(description = "Returns HmacSHA256 MAC for the given key and data Base64 encoded")
	public String hmacSha256(@VsoParam(description="Secret Key Base64 encoded") String keyB64,
							@VsoParam(description="Data to sign Base64 encoded") String dataB64) {
		return service.hmacSha256(keyB64, dataB64);
	}

	@VsoMethod(description = "Returns HmacSHA384 MAC for the given key and data Base64 encoded")
	public String hmacSha384(@VsoParam(description="Secret Key Base64 encoded") String keyB64,
							@VsoParam(description="Data to sign Base64 encoded") String dataB64) {
		return service.hmacSha384(keyB64, dataB64);
	}

	@VsoMethod(description = "Returns HmacSHA512 MAC for the given key and data Base64 encoded")
	public String hmacSha512(@VsoParam(description="Secret Key Base64 encoded") String keyB64,
							@VsoParam(description="Data to sign Base64 encoded") String dataB64) {
		return service.hmacSha512(keyB64, dataB64);
	}
}
