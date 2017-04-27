/*
 * Copyright (c) 2017 VMware, Inc. All Rights Reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */
package com.vmware.o11n.plugin.crypto.model;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.util.Arrays;
import org.springframework.stereotype.Component;

import ch.dunes.model.fileattachment.MimeAttachment;

@Component
public class CryptoEncodingService {

	/**
	 *
	 * @param data
	 * @return
	 */
	public String base64Encode(String data) {
		String encoded = new String(Base64.encodeBase64(data.getBytes()));
		return encoded;
	}

	/**
	 *
	 * @param b64data
	 * @return
	 */
	public String base64Decode(String b64data) {
		String decoded = new String(Base64.decodeBase64(b64data));
		return decoded;
	}

	/**
	 *
	 * @param b64data
	 * @return
	 */
	public String base64toHex(String b64data) {
		String hexDataString = Hex.encodeHexString(Base64.decodeBase64(b64data));
		return hexDataString;
	}

	/**
	 *
	 * @param hex
	 * @return
	 * @throws DecoderException
	 */
	public String hexToBase64(String hex) throws DecoderException {
		String b64data = new String(Base64.encodeBase64(Hex.decodeHex(hex.toCharArray())));
		return b64data;
	}

	/**
	 *
	 * @param b64data
	 * @param mimeType
	 * @param fileName
	 * @return
	 */
	public MimeAttachment base64ToMime(String b64data, String mimeType, String fileName ) {
		MimeAttachment mime = new MimeAttachment();
		mime.setContent(Base64.decodeBase64(b64data));
		mime.setMimeType(mimeType);
		mime.setName(fileName);
		return mime;
	}

	/**
	 *
	 * @param mime
	 * @return Base64 encoded string
	 */
	public String mimeToBase64(MimeAttachment mime ) {
		byte[] mimeBytes = mime.getContent();
		return Base64.encodeBase64String(mimeBytes);
	}

	/**
	 *
	 * @param b64data1
	 * @param b64data2
	 * @return
	 */
	public String binaryConcatBase64(String b64data1, String b64data2) {
		byte[] data1 = Base64.decodeBase64(b64data1);
		byte[] data2 = Base64.decodeBase64(b64data2);

		int totalSize = data1.length + data2.length;

		byte[] both = Arrays.copyOf(data1, totalSize);
		System.arraycopy(data2, 0, both, data1.length, data2.length);

		return Base64.encodeBase64String(both);
	}

	/**
	 *
	 * @param b64data
	 * @return
	 */
	public int getLengthBase64(String b64data) {
		byte[] data = Base64.decodeBase64(b64data);
		return data.length;
	}

	/**
	 *
	 *
	 * @param b64data
	 * @param start
	 * @param length
	 * @return
	 */
	public String getSubsetBase64(String b64data, int start, int length) {
		byte[] data = Base64.decodeBase64(b64data);
		if ((start + length) > data.length) {
			throw new IndexOutOfBoundsException("Length from start exceeds bounds of data");
		}
		byte[] subset = new byte[length];
		System.arraycopy(data, start, subset, 0, length);
		return Base64.encodeBase64String(subset);
	}
}
