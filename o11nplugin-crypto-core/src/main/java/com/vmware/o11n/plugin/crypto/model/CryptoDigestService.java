/*
 * Copyright (c) 2017 VMware, Inc. All Rights Reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */
package com.vmware.o11n.plugin.crypto.model;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.codec.digest.HmacUtils;
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


	/**
	 * HmacMD5
	 *
	 * @param keyB64 Secret key Base64 encoded
	 * @param dataB64 Data to sign Base64 encoded
	 * @return HmacMd5 MAC for the given key and data Base64 encoded
	 */
	public String hmacMd5(String keyB64, String dataB64) {
		validateB64(keyB64);
		validateB64(dataB64);
		final byte[] key = Base64.decodeBase64(keyB64);
		final byte[] data = Base64.decodeBase64(dataB64);

		return Base64.encodeBase64String(HmacUtils.hmacMd5(key, data));
	}

	/**
	 * HmacSHA1
	 *
	 * @param keyB64 Secret key Base64 encoded
	 * @param dataB64 Data to sign Base64 encoded
	 * @return HmacSha1 MAC for the given key and data Base64 encoded
	 */
	public String hmacSha1(String keyB64, String dataB64) {
		validateB64(keyB64);
		validateB64(dataB64);
		final byte[] key = Base64.decodeBase64(keyB64);
		final byte[] data = Base64.decodeBase64(dataB64);

		return Base64.encodeBase64String(HmacUtils.hmacSha1(key, data));
	}

	/**
	 * HmacSHA256
	 *
	 * @param keyB64 Secret key Base64 encoded
	 * @param dataB64 Data to sign Base64 encoded
	 * @return HmacSha256 MAC for the given key and data Base64 encoded
	 */
	public String hmacSha256(String keyB64, String dataB64) {
		validateB64(keyB64);
		validateB64(dataB64);
		final byte[] key = Base64.decodeBase64(keyB64);
		final byte[] data = Base64.decodeBase64(dataB64);

		return Base64.encodeBase64String(HmacUtils.hmacSha256(key, data));
	}

	/**
	 * HmacSHA384
	 *
	 * @param keyB64 Secret key Base64 encoded
	 * @param dataB64 Data to sign Base64 encoded
	 * @return HmacSha384 MAC for the given key and data Base64 encoded
	 */
	public String hmacSha384(String keyB64, String dataB64) {
		validateB64(keyB64);
		validateB64(dataB64);
		final byte[] key = Base64.decodeBase64(keyB64);
		final byte[] data = Base64.decodeBase64(dataB64);

		return Base64.encodeBase64String(HmacUtils.hmacSha384(key, data));
	}

	/**
	 * HmacSHA512
	 *
	 * @param keyB64 Secret key Base64 encoded
	 * @param dataB64 Data to sign Base64 encoded
	 * @return HmacSha512 MAC for the given key and data Base64 encoded
	 */
	public String hmacSha512(String keyB64, String dataB64) {
		validateB64(keyB64);
		validateB64(dataB64);
		final byte[] key = Base64.decodeBase64(keyB64);
		final byte[] data = Base64.decodeBase64(dataB64);

		return Base64.encodeBase64String(HmacUtils.hmacSha512(key, data));
	}

	private void validateB64(String dataB64) {
		if (!Base64.isBase64(dataB64)) {
			throw new IllegalArgumentException("Expecting base64 encoded data.  Use CryptoEncoding.base64Encode() against this string before attempting to hash it");
		}
	}

}
