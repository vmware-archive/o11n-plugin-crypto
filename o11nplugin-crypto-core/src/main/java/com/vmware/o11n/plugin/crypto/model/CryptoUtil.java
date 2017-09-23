/*
 * Copyright (c) 2017 VMware, Inc. All Rights Reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */
package com.vmware.o11n.plugin.crypto.model;

import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CryptoUtil {
	private final static Logger log = LoggerFactory.getLogger(CryptoUtil.class);

	private final static String FIVE_DASH = "-----";

	/**
	 * Sometimes the line endings can unintentially get stripped by a user in the vRO client.
	 * This function attempts to rebuild a PEM string with the expected line length and line endings
	 *
	 * @param pem
	 *
	 * returns a properly formed PEM string
	 */
	public static String fixPemString(String pem) {

		final Pattern pemP = Pattern.compile(FIVE_DASH + "(.*)" + FIVE_DASH + "([\\s\\S]*)" + FIVE_DASH +"(.*)" + FIVE_DASH);
		final Matcher pemM = pemP.matcher(pem);

		String header = "";
		String data = "";
		String footer = "";

		if (pemM.find() && pemM.groupCount() == 3) {
			header = pemM.group(1).trim();
			data = pemM.group(2).trim();
			footer = pemM.group(3).trim();
		} else {
			log.error("Could not parse pem parts. Either the RegEx couldn't find a PEM format or the 3 parts of a PEM couldn't be found.");
			throw new RuntimeException("Could not parse pem parts");
		}
		ArrayList<String> dataParts = splitOnNumChars(data, 64);

		StringBuilder newPem = new StringBuilder();

		newPem.append(FIVE_DASH).append(header).append(FIVE_DASH).append("\n");
		for (String part : dataParts){
			newPem.append(part).append("\n");
		}
		newPem.append(FIVE_DASH).append(footer).append(FIVE_DASH);

		return newPem.toString();
	}

	/**
	 *
	 * @param input
	 * @param numChars
	 * @return
	 */
	public static ArrayList<String> splitOnNumChars(String input, Integer numChars) {
		final Pattern pattern = Pattern.compile("\r\n|\n|\r");
		final Matcher matcher = pattern.matcher(input);
		String singleLine = matcher.replaceAll("");

		ArrayList<String> output = new ArrayList<>();

		while (singleLine.length() > 0) {
			String nextEntry = singleLine.substring(0,Math.min(numChars, singleLine.length()));
			output.add(nextEntry);
			singleLine = singleLine.substring(Math.min(numChars, singleLine.length()));
		}

		return output;
	}

	/**
	 * PEM encode a public key
	 *
	 * @param pubKey Public
	 * @return PEM encoded public key string
	 */
	public static String pemEncode(PublicKey pubKey) {
		String toReturn;
		if (pubKey instanceof RSAPublicKey) {
			final String keyHeader = FIVE_DASH + "BEGIN PUBLIC KEY"+ FIVE_DASH;
			final String keyFooter = FIVE_DASH + "END PUBLIC KEY" + FIVE_DASH;
			Base64 encoder = new Base64(64);
			toReturn = String.join("\n", keyHeader, new String(encoder.encode(pubKey.getEncoded())), keyFooter);
		} else {
			throw new UnsupportedOperationException("Unknown public key type.  Only implemented for RSAPublicKey.");
		}
		return CryptoUtil.fixPemString(toReturn);
	}

	/**
	 * PEM encode a certificate
	 *
	 * @param pubKey Public
	 * @return PEM encoded certificate string
	 * @throws CertificateEncodingException
	 */
	public static String pemEncode(Certificate cert) throws CertificateEncodingException {
		String toReturn;
		if (cert instanceof X509Certificate) {
			final String certHeader = FIVE_DASH + "BEGIN CERTIFICATE" + FIVE_DASH;
			final String certFooter = FIVE_DASH + "END CERTIFICATE" + FIVE_DASH;
			Base64 encoder = new Base64(64);
			toReturn = String.join("\n", certHeader, new String(encoder.encode(cert.getEncoded())), certFooter);
		} else {
			throw new UnsupportedOperationException("Unknown certificate type.  Only implemented for X509Certificate.");
		}
		return CryptoUtil.fixPemString(toReturn);
	}
}
