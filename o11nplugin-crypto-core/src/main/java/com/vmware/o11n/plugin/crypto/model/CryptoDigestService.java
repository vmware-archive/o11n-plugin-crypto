/*
 * Copyright (c) 2017 VMware, Inc. All Rights Reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */
package com.vmware.o11n.plugin.crypto.model;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.stereotype.Component;

@Component
public class CryptoDigestService {

	public String md5(String data) {
		return Base64.encodeBase64String(DigestUtils.md5(data));
	}
	public String md5Base64(String dataB64) {
		validateB64(dataB64);
		return Base64.encodeBase64String(DigestUtils.md5(Base64.decodeBase64(dataB64)));
	}

	public String sha1(String data) {
		return Base64.encodeBase64String(DigestUtils.sha1(data));
	}
	public String sha1Base64(String dataB64) {
		validateB64(dataB64);
		return Base64.encodeBase64String(DigestUtils.sha1(Base64.decodeBase64(dataB64)));
	}

	public String sha256(String data) {
		return Base64.encodeBase64String(DigestUtils.sha256(data));
	}
	public String sha256Base64(String dataB64) {
		validateB64(dataB64);
		return Base64.encodeBase64String(DigestUtils.sha256(Base64.decodeBase64(dataB64)));
	}

	public String sha384(String data) {
		return Base64.encodeBase64String(DigestUtils.sha384(data));
	}
	public String sha384Base64(String dataB64) {
		validateB64(dataB64);
		return Base64.encodeBase64String(DigestUtils.sha384(Base64.decodeBase64(dataB64)));
	}

	public String sha512(String data) {
		return Base64.encodeBase64String(DigestUtils.sha512(data));
	}
	public String sha512Base64(String dataB64) {
		validateB64(dataB64);
		return Base64.encodeBase64String(DigestUtils.sha512(Base64.decodeBase64(dataB64)));
	}

	private void validateB64(String dataB64) {
		if (!Base64.isBase64(dataB64)) {
			throw new IllegalArgumentException("Expecting base64 encoded data.  Use CryptoEncoding.base64Encode() against this string before attempting to hash it");
		}
	}
}
