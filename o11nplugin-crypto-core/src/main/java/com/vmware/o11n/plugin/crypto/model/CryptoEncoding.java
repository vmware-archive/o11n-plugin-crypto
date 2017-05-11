/*
 * Copyright (c) 2017 VMware, Inc. All Rights Reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */
package com.vmware.o11n.plugin.crypto.model;

import java.io.UnsupportedEncodingException;

import org.apache.commons.codec.DecoderException;
import org.springframework.beans.factory.annotation.Autowired;

import com.vmware.o11n.plugin.sdk.annotation.VsoMethod;
import com.vmware.o11n.plugin.sdk.annotation.VsoObject;
import com.vmware.o11n.plugin.sdk.annotation.VsoParam;
import com.vmware.o11n.plugin.sdk.spring.AbstractSpringPluginFactory;

import ch.dunes.model.fileattachment.MimeAttachment;
import ch.dunes.vso.sdk.api.IPluginFactory;

@VsoObject(
create=false,
strict=true,
singleton=true,
description="Provides methods to encode/decode strings between different encodings")

public class CryptoEncoding {
	public static final String TYPE = "CryptoEncoding";

	@Autowired
	private CryptoEncodingService service;

	public static CryptoEncoding createScriptingSingleton(IPluginFactory factory) {
		return ((AbstractSpringPluginFactory) factory).createScriptingObject(CryptoEncoding.class);
	}

	@VsoMethod(description="Base64 Encoder")
	public String base64Encode(@VsoParam(description="Data to encode") String data) throws UnsupportedEncodingException {
		return service.base64Encode(data);
	}

	@VsoMethod(description="Base64 Decoder")
	public String base64Decode(@VsoParam(description="Base64 data to decode") String b64data) {
		return service.base64Decode(b64data);
	}

	@VsoMethod(description="Base64 to Hex Encoder")
	public String base64toHex(@VsoParam(description="Base64 data to convert to Hex") String b64data) {
		return service.base64toHex(b64data);
	}

	@VsoMethod(description="Hex to Base64 Encoder")
	public String hexToBase64(@VsoParam(description="Hex data to convert to Base64") String hex) throws DecoderException {
		return service.hexToBase64(hex);
	}

	@VsoMethod(description="Base64 to MimeAttachment",vsoReturnType="MimeAttachment")
	public MimeAttachment base64ToMime(
			@VsoParam(description="Base64 encoded data") String b64data,
			@VsoParam(description="Mime type of data") String mimeType,
			@VsoParam(description="Filename of MimeAttachment") String fileName) {
		return service.base64ToMime(b64data, mimeType, fileName);
	}

	@VsoMethod(description="Extracts data from MimeAttachment as Base64")
	public String mimeToBase64(@VsoParam(description="",vsoType="MimeAttachment") MimeAttachment mime) {
		return service.mimeToBase64(mime);
	}

	@VsoMethod(description="Decodes two Base64 strings and concatenates the binary data. Returns base64 encoded result")
	public String binaryConcatBase64(
			@VsoParam(description="First Base64 encoded data") String b64data1,
			@VsoParam(description="Second Base64 encoded data to append") String b64data2) {
		return service.binaryConcatBase64(b64data1, b64data2);
	}

	@VsoMethod(description="Decodes a Base64 String and returns the number of bytes that were encoded.",vsoReturnType="Number")
	public int getLengthBase64(@VsoParam(description="Base64 data")  String b64data) {
		return service.getLengthBase64(b64data);
	}

	@VsoMethod(description="Returns a subset of bytes from a Base64 encoded string")
	public String getSubsetBase64(
			@VsoParam(description="Base64 data") String b64data,
			@VsoParam(description="Starting byte index to get subset of data (inclusive). Starts at 0",vsoType="Number") int start,
			@VsoParam(description="number of bytes to return.  Must be 1 or greater",vsoType="Number") int length) {
		if (length < 1) {
			throw new IllegalArgumentException("length must be 1 or greater");
		}
		if (start < 0) {
			throw new IllegalArgumentException("start must be 0 or greater");
		}
		return service.getSubsetBase64(b64data, start, length);
	}

}
