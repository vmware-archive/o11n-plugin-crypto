/*
 * Copyright (c) 2017 VMware, Inc. All Rights Reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */
package com.vmware.o11n.plugin.crypto;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import com.vmware.o11n.plugin.crypto.model.CryptoUtil;

public class CryptoUtilTest {

	@Test
	public void fixPem() {
		assertEquals("Fix Private PEM String one line",CryptoTestData.privatePem, CryptoUtil.fixPemString(CryptoTestData.privatePemOneLine));
		assertEquals("Fix Private PEM String",CryptoTestData.privatePem, CryptoUtil.fixPemString(CryptoTestData.privatePem));
		assertEquals("Fix Public PEM String one line",CryptoTestData.publicPem, CryptoUtil.fixPemString(CryptoTestData.publicPemOneLine));
		assertEquals("Fix Public PEM String",CryptoTestData.publicPem, CryptoUtil.fixPemString(CryptoTestData.publicPem));
	}
}
