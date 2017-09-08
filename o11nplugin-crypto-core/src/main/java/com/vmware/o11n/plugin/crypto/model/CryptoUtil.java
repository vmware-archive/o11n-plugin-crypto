/*
 * Copyright (c) 2017 VMware, Inc. All Rights Reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */
package com.vmware.o11n.plugin.crypto.model;

import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CryptoUtil {

	/**
	 * Sometimes the line endings can unintentially get stripped by a user in the vRO client.
	 * This function attempts to rebuild a PEM string with the expected line length and line endings
	 *
	 * @param pem
	 *
	 * returns a properly formed PEM string
	 */
	public static String fixPemString(String pem) {
		final String FIVE_DASH = "-----";
		Pattern pemP = Pattern.compile("-----(.*)-----([\\s\\S]*)-----(.*)-----");
		Matcher pemM = pemP.matcher(pem);

		String header = "";
		String data = "";
		String footer = "";

		if (pemM.find() && pemM.groupCount() == 3) {
			header = pemM.group(1).trim();
			data = pemM.group(2).trim();
			footer = pemM.group(3).trim();
		} else {
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
		Pattern pattern = Pattern.compile("\r\n|\n|\r");
		Matcher matcher = pattern.matcher(input);
		String singleLine = matcher.replaceAll("");

		ArrayList<String> output = new ArrayList<>();

		while (singleLine.length() > 0) {
			String nextEntry = singleLine.substring(0,Math.min(numChars, singleLine.length()));
			output.add(nextEntry);
			singleLine = singleLine.substring(Math.min(numChars, singleLine.length()));
		}

		return output;
	}

}
