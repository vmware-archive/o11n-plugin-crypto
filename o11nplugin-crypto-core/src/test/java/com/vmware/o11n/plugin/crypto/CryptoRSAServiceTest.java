/*
 * Copyright (c) 2017 VMware, Inc. All Rights Reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */
package com.vmware.o11n.plugin.crypto;
import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.junit.Test;

import com.vmware.o11n.plugin.crypto.model.CryptoEncryptionService;
import com.vmware.o11n.plugin.crypto.model.CryptoRSAService;

public class CryptoRSAServiceTest {

	//2048 bit private key
	private final String privatePem = String.join("\n",
		"-----BEGIN RSA PRIVATE KEY-----",
		"MIIEogIBAAKCAQEAnM7U1Z3bJSU+SugQu4fIBq/09oosiz8hbHulG0DPeapR8lRH",
		"wE/yarAmLUsHcXvGvFlsdDcP6qakqFRyz8xcv7SgOnOLX+Ss7a+y+kj1Oq9a2Toj",
		"91vFznDoOhGMRjQxT6/NrtiiXuR90Rs0vESZQf9dSIbSPa0fj8KJE/01VjbycVHE",
		"PDmqZY2U6kc8kICIQWh+54rkWFPCsGTYDpCUEtbzbf/EyjV6OnqV7cYgVhqumuXO",
		"5wipo5gnYoFXSW/nsE+6TwBb6tu5z11Ul1J4xok4+R9YIe5jk8t6zziT/yZUdIM6",
		"47CsuCwQmn/tdZpEEAaWIKzLDeYBwJ8OCRoaOwIDAQABAoIBAGNRKULHgbasOSEu",
		"jPKKFKoPpmLEr2Per2fLhI6XZRGVS+Pld7CZslvah8OmQueg0wYWyXduLJmdxKqN",
		"Gk79DD2rxNRgvIUXDGRbJUwbC5+I00zE42TXbpjLsHqfBK6ufhEPs4Gr2mOp6vqX",
		"dbZM6JkBie7W3bCMx3HBcBsGBFM+6ktmGGnbH0KBNlGZn1RHHGGU/EQl1R3KQgAl",
		"XqNB56tuARH0GhNYBxarBZ92U/DEuo3JkfB258pfE7dFt75KumMq+kdcPo5QSfO1",
		"qBBToLKumT52NVn1PfNcnxZFTTKnmvcvLWnsBJmf9X1kGG2/UPyf8ebfntliJ/N8",
		"/QZPJhkCgYEAytcd/PtskTblA4h9sC9eV5sjyLQyE+ImzZ+juYUFQSaZ5QXg+Qta",
		"BsQcftaRe7tKZ0vMa59IqGzTschCwuSNtsFZTEqM9QmrOmAs81MKhfDxnhLGCG+O",
		"Z3LHCbHJwhWNJdOoAbIS92Ww9oeT5ISbL9l8seo32Al2C/hwQqCso6UCgYEAxedU",
		"HWYXfPKJTod57BwFCHC6PMiL6kyGeKfKSQhUObJC6YOTgzcDy4o87svj8nLCPvFh",
		"Kjtw43ksBVFcwzRAToM8SNBdSUwzKqbmpQiVR9ljs4NltwkgkRQq0YRsznis9o/4",
		"I2wo8FobPgJCqysCCOV2lzI14kEmCUwwWHcl4F8CgYAiQYoy+1MugxLSMe7oHlfU",
		"e8LjVmtOqFbdSySfZDOq+RXsc7220Y/2rJATa7FOMCc0orx3QINIznhCAgwkVe0I",
		"/EZUeBKuH1/nj+6HeXLBhBuKEqmXKx/loKC0pm3odTNNPB2Xi7dgSLBGMkdrxGlg",
		"/13rvh6IQbDJ/L8YwYHmcQKBgEYHAxacB3epArkM6zGHAKjp6pyTgh7YEUUkaknJ",
		"brQzxcWHT21AzFD7i3AcKX6i6OUI2I7vFZUITXFcRuyz0oV1nqFNSZUkJ37SLA79",
		"qIUSAVuGBTntOt7bOgOFTlMJFHrymqU+IoZZ/AXHGvwibcfkGkCJ/dMfpmvnz7ud",
		"/YMVAoGAVoPjwSO8+J2Bpe/ertgYy5I1AJ6UyR2lvEI/ZETOcKzyEz04zTfjhZkA",
		"dUUn4Uq+Fs2ltYKgiXlrIBMHdTf8CLsqwBtjjXdmjVOiJzKOlwDyviHU/ie5xXdp",
		"pMF+rxLq1oCOxoYwf3TSgXKjnP3sYcvOWFApN9bljqS1jtMhnjg=",
		"-----END RSA PRIVATE KEY-----");

	private final String privatePemOneLine = String.join("",
		"-----BEGIN RSA PRIVATE KEY-----",
		"MIIEogIBAAKCAQEAnM7U1Z3bJSU+SugQu4fIBq/09oosiz8hbHulG0DPeapR8lRH",
		"wE/yarAmLUsHcXvGvFlsdDcP6qakqFRyz8xcv7SgOnOLX+Ss7a+y+kj1Oq9a2Toj",
		"91vFznDoOhGMRjQxT6/NrtiiXuR90Rs0vESZQf9dSIbSPa0fj8KJE/01VjbycVHE",
		"PDmqZY2U6kc8kICIQWh+54rkWFPCsGTYDpCUEtbzbf/EyjV6OnqV7cYgVhqumuXO",
		"5wipo5gnYoFXSW/nsE+6TwBb6tu5z11Ul1J4xok4+R9YIe5jk8t6zziT/yZUdIM6",
		"47CsuCwQmn/tdZpEEAaWIKzLDeYBwJ8OCRoaOwIDAQABAoIBAGNRKULHgbasOSEu",
		"jPKKFKoPpmLEr2Per2fLhI6XZRGVS+Pld7CZslvah8OmQueg0wYWyXduLJmdxKqN",
		"Gk79DD2rxNRgvIUXDGRbJUwbC5+I00zE42TXbpjLsHqfBK6ufhEPs4Gr2mOp6vqX",
		"dbZM6JkBie7W3bCMx3HBcBsGBFM+6ktmGGnbH0KBNlGZn1RHHGGU/EQl1R3KQgAl",
		"XqNB56tuARH0GhNYBxarBZ92U/DEuo3JkfB258pfE7dFt75KumMq+kdcPo5QSfO1",
		"qBBToLKumT52NVn1PfNcnxZFTTKnmvcvLWnsBJmf9X1kGG2/UPyf8ebfntliJ/N8",
		"/QZPJhkCgYEAytcd/PtskTblA4h9sC9eV5sjyLQyE+ImzZ+juYUFQSaZ5QXg+Qta",
		"BsQcftaRe7tKZ0vMa59IqGzTschCwuSNtsFZTEqM9QmrOmAs81MKhfDxnhLGCG+O",
		"Z3LHCbHJwhWNJdOoAbIS92Ww9oeT5ISbL9l8seo32Al2C/hwQqCso6UCgYEAxedU",
		"HWYXfPKJTod57BwFCHC6PMiL6kyGeKfKSQhUObJC6YOTgzcDy4o87svj8nLCPvFh",
		"Kjtw43ksBVFcwzRAToM8SNBdSUwzKqbmpQiVR9ljs4NltwkgkRQq0YRsznis9o/4",
		"I2wo8FobPgJCqysCCOV2lzI14kEmCUwwWHcl4F8CgYAiQYoy+1MugxLSMe7oHlfU",
		"e8LjVmtOqFbdSySfZDOq+RXsc7220Y/2rJATa7FOMCc0orx3QINIznhCAgwkVe0I",
		"/EZUeBKuH1/nj+6HeXLBhBuKEqmXKx/loKC0pm3odTNNPB2Xi7dgSLBGMkdrxGlg",
		"/13rvh6IQbDJ/L8YwYHmcQKBgEYHAxacB3epArkM6zGHAKjp6pyTgh7YEUUkaknJ",
		"brQzxcWHT21AzFD7i3AcKX6i6OUI2I7vFZUITXFcRuyz0oV1nqFNSZUkJ37SLA79",
		"qIUSAVuGBTntOt7bOgOFTlMJFHrymqU+IoZZ/AXHGvwibcfkGkCJ/dMfpmvnz7ud",
		"/YMVAoGAVoPjwSO8+J2Bpe/ertgYy5I1AJ6UyR2lvEI/ZETOcKzyEz04zTfjhZkA",
		"dUUn4Uq+Fs2ltYKgiXlrIBMHdTf8CLsqwBtjjXdmjVOiJzKOlwDyviHU/ie5xXdp",
		"pMF+rxLq1oCOxoYwf3TSgXKjnP3sYcvOWFApN9bljqS1jtMhnjg=",
		"-----END RSA PRIVATE KEY-----");

	//the respective public key
	private final String publicPem = String.join("\n",
		"-----BEGIN PUBLIC KEY-----",
		"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnM7U1Z3bJSU+SugQu4fI",
		"Bq/09oosiz8hbHulG0DPeapR8lRHwE/yarAmLUsHcXvGvFlsdDcP6qakqFRyz8xc",
		"v7SgOnOLX+Ss7a+y+kj1Oq9a2Toj91vFznDoOhGMRjQxT6/NrtiiXuR90Rs0vESZ",
		"Qf9dSIbSPa0fj8KJE/01VjbycVHEPDmqZY2U6kc8kICIQWh+54rkWFPCsGTYDpCU",
		"Etbzbf/EyjV6OnqV7cYgVhqumuXO5wipo5gnYoFXSW/nsE+6TwBb6tu5z11Ul1J4",
		"xok4+R9YIe5jk8t6zziT/yZUdIM647CsuCwQmn/tdZpEEAaWIKzLDeYBwJ8OCRoa",
		"OwIDAQAB",
		"-----END PUBLIC KEY-----");
	private final String publicPemOneLine = String.join("",
		"-----BEGIN PUBLIC KEY-----",
		"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnM7U1Z3bJSU+SugQu4fI",
		"Bq/09oosiz8hbHulG0DPeapR8lRHwE/yarAmLUsHcXvGvFlsdDcP6qakqFRyz8xc",
		"v7SgOnOLX+Ss7a+y+kj1Oq9a2Toj91vFznDoOhGMRjQxT6/NrtiiXuR90Rs0vESZ",
		"Qf9dSIbSPa0fj8KJE/01VjbycVHEPDmqZY2U6kc8kICIQWh+54rkWFPCsGTYDpCU",
		"Etbzbf/EyjV6OnqV7cYgVhqumuXO5wipo5gnYoFXSW/nsE+6TwBb6tu5z11Ul1J4",
		"xok4+R9YIe5jk8t6zziT/yZUdIM647CsuCwQmn/tdZpEEAaWIKzLDeYBwJ8OCRoa",
		"OwIDAQAB",
		"-----END PUBLIC KEY-----");

	private final String staticStringB64 = "SGVsbG8gV29ybGQhIQ==";

	CryptoRSAService service = new CryptoRSAService();
	CryptoEncryptionService encryptionService = new CryptoEncryptionService();

	@Test
	public void staticRSAEncryptTest() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {
		String encryptedB64 = service.encrypt(publicPem, staticStringB64);
		String decryptedB64 = service.decrypt(privatePem, encryptedB64);
		assertEquals("RSA Static", staticStringB64, decryptedB64);
	}

	@Test (expected=IllegalArgumentException.class)
	public void wrongKeyRSAEncrypt() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {
		String encryptedB64 = service.encrypt(publicPem, staticStringB64);
		String decryptedB64 = service.decrypt(publicPem, encryptedB64); //should fail
		assertEquals("RSA Static", staticStringB64, decryptedB64);
	}

	@Test
	public void randomRSAEncryptTest() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {
		final String dataB64 = encryptionService.generateRandomBytes(245);
		String encryptedB64 = service.encrypt(publicPem, dataB64);
		String decryptedB64 = service.decrypt(privatePem, encryptedB64);
		assertEquals("RSA Dynamic", dataB64, decryptedB64);
	}

	@Test (expected=IllegalBlockSizeException.class)
	public void randomRSAEncryptTestExcessiveData() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {
		final String dataB64 = encryptionService.generateRandomBytes(246);
		String encryptedB64 = service.encrypt(publicPem, dataB64);  //should fail
		String decryptedB64 = service.decrypt(privatePem, encryptedB64);
		assertEquals("RSA Dynamic", dataB64, decryptedB64);
	}

	@Test
	public void randomRSAEncryptPrivatePrivateTest() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {
		final String dataB64 = encryptionService.generateRandomBytes(245);
		String encryptedB64 = service.encrypt(privatePem, dataB64);
		String decryptedB64 = service.decrypt(privatePem, encryptedB64);
		assertEquals("RSA Dynamic", dataB64, decryptedB64);
	}

	@Test
	public void signAndVerify() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, IOException {
		String sigB64 = service.sign(privatePem, staticStringB64);
		boolean valid = service.verifySignature(publicPem, staticStringB64, sigB64);
		assertEquals("Sign and Verify", true, valid);
	}

	@Test
	public void signAndVerifyOneLine() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, IOException {
		String sigB64 = service.sign(privatePemOneLine, staticStringB64);
		boolean valid = service.verifySignature(publicPemOneLine, staticStringB64, sigB64);
		assertEquals("Sign and Verify One Line PEMs", true, valid);
	}

	@Test
	public void signAndVerifyPrivatePrivate() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, IOException {
		String sigB64 = service.sign(privatePem, staticStringB64);
		boolean valid = service.verifySignature(privatePem, staticStringB64, sigB64);
		assertEquals("Sign and Verify Private Private", true, valid);
	}

	@Test (expected=SignatureException.class)
	public void signAndVerifyRandomLarge() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, IOException {
		final String dataB64 = encryptionService.generateRandomBytes(2453);
		String sigB64 = service.sign(privatePem, dataB64); //should fail
		boolean valid = service.verifySignature(publicPem, dataB64, sigB64);
		assertEquals("Sign and Verify Large", true, valid);
	}

	@Test
	public void signAndVerifyRandom() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, IOException {
		final String dataB64 = encryptionService.generateRandomBytes(245);
		String sigB64 = service.sign(privatePem, dataB64);
		boolean valid = service.verifySignature(publicPem, dataB64, sigB64);
		assertEquals("Sign and Verify Random", true, valid);
	}

	@Test
	public void fixPem() {
		assertEquals("Fix Private PEM String one line",privatePem, service.fixPemString(privatePemOneLine));
		assertEquals("Fix Private PEM String",privatePem, service.fixPemString(privatePem));
		assertEquals("Fix Public PEM String one line",publicPem, service.fixPemString(publicPemOneLine));
		assertEquals("Fix Public PEM String",publicPem, service.fixPemString(publicPem));
	}

	@Test
	public void rsaRandomEncryptOneLinePem() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {
		final String dataB64 = encryptionService.generateRandomBytes(245);
		String encryptedB64 = service.encrypt(publicPemOneLine, dataB64);
		String decryptedB64 = service.decrypt(privatePemOneLine, encryptedB64);
		assertEquals("RSA Dynamic One line PEMs", dataB64, decryptedB64);
	}

}