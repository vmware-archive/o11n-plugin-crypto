/*
 * Copyright (c) 2017 VMware, Inc. All Rights Reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */
package com.vmware.o11n.plugin.crypto;

public class CryptoTestData {

	public static final String staticString = "Hello World!!";
	public static final String staticStringB64 = "SGVsbG8gV29ybGQhIQ==";
	public static final String staticB32foobar = "MZXW6YTBOI======";
	public static final String staticB32fooba = "MZXW6YTB";

	public static final String staticSecret = "VMware1!";


	//2048 bit private key
	public static final String privatePem = String.join("\n",
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

	public static final String privatePemOneLine = String.join("",
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
	public static final String publicPem = String.join("\n",
		"-----BEGIN PUBLIC KEY-----",
		"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnM7U1Z3bJSU+SugQu4fI",
		"Bq/09oosiz8hbHulG0DPeapR8lRHwE/yarAmLUsHcXvGvFlsdDcP6qakqFRyz8xc",
		"v7SgOnOLX+Ss7a+y+kj1Oq9a2Toj91vFznDoOhGMRjQxT6/NrtiiXuR90Rs0vESZ",
		"Qf9dSIbSPa0fj8KJE/01VjbycVHEPDmqZY2U6kc8kICIQWh+54rkWFPCsGTYDpCU",
		"Etbzbf/EyjV6OnqV7cYgVhqumuXO5wipo5gnYoFXSW/nsE+6TwBb6tu5z11Ul1J4",
		"xok4+R9YIe5jk8t6zziT/yZUdIM647CsuCwQmn/tdZpEEAaWIKzLDeYBwJ8OCRoa",
		"OwIDAQAB",
		"-----END PUBLIC KEY-----");
	public static final String publicPemOneLine = String.join("",
		"-----BEGIN PUBLIC KEY-----",
		"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnM7U1Z3bJSU+SugQu4fI",
		"Bq/09oosiz8hbHulG0DPeapR8lRHwE/yarAmLUsHcXvGvFlsdDcP6qakqFRyz8xc",
		"v7SgOnOLX+Ss7a+y+kj1Oq9a2Toj91vFznDoOhGMRjQxT6/NrtiiXuR90Rs0vESZ",
		"Qf9dSIbSPa0fj8KJE/01VjbycVHEPDmqZY2U6kc8kICIQWh+54rkWFPCsGTYDpCU",
		"Etbzbf/EyjV6OnqV7cYgVhqumuXO5wipo5gnYoFXSW/nsE+6TwBb6tu5z11Ul1J4",
		"xok4+R9YIe5jk8t6zziT/yZUdIM647CsuCwQmn/tdZpEEAaWIKzLDeYBwJ8OCRoa",
		"OwIDAQAB",
		"-----END PUBLIC KEY-----");

	//hmacSha1 sample data from AWS docs
	public static final String stringToSign = "GET\n\n\nTue, 27 Mar 2007 19:36:42 +0000\n/johnsmith/photos/puppy.jpg";
	public static final String sampleKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
	public static final String expectedHmacSha1SigB64 = "bWq2s1WEIj+Ydj0vQ697zp+IXMU=";

	public static final String hmacData = "The quick brown fox jumps over the lazy dog";
	public static final String hmacKey = "key";
	public static final String hmacMd5ExpectedHex = "80070713463e7749b90c2dc24911e275";
	public static final String hmacSha1ExpectedHex = "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9";
	public static final String hmacSha256ExpectedHex = "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8";

	public static final String vcsa_01aCert = String.join("\n",
			"-----BEGIN CERTIFICATE-----",
			"MIIFnTCCA4WgAwIBAgIBAzANBgkqhkiG9w0BAQsFADCBjzELMAkGA1UEBhMCVVMx",
			"EzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xEzAR",
			"BgNVBAoMCkJvZ3VzIEluYy4xEzARBgNVBAsMCk9wZXJhdGlvbnMxKTAnBgNVBAMM",
			"IEJvZ3VzIEluYy4gQ2VydGlmaWNhdGUgQXV0aG9yaXR5MB4XDTE3MDgyNDAzNTM0",
			"N1oXDTE5MDgyNDAzNTM0N1owdzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlm",
			"b3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xEzARBgNVBAoMCkJvZ3VzIElu",
			"Yy4xEzARBgNVBAsMCk9wZXJhdGlvbnMxETAPBgNVBAMMCHZjc2EtMDFhMIIBIjAN",
			"BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz3WgSFUJjKEc7P7VfnsHounTpE69",
			"qzovgejlV7nIFjnNYnMAzG9kSNbob/cHhgcw8qGVR+zWyxfpZVe2KEy/Oryhs4kZ",
			"2P5sJRJOOVVIoZ/FLXbBb44FTKsoiqBInh0KrJkQm/1yh+vpkORlN8dQZPdQiA++",
			"mt1d7xNWfXqDCmm+1uYl+zhsXSz16CmIXXs1m02vpKtAoMBjpC/3UiHVSni6XYSO",
			"gaBT5pdqZ6z52sXvIvfcaJcxMtBGiLp1Y3IIbQuN6HCr8H+jM+Qhx4jtvkt8/wva",
			"1CoVbB1132+yFD72isv6hoZ7/Tfpdk4AjdhuQLrP44KQyaJnbtRC1M5fSwIDAQAB",
			"o4IBGTCCARUwDgYDVR0PAQH/BAQDAgWgMAkGA1UdEwQCMAAwHQYDVR0lBBYwFAYI",
			"KwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBQeF8RXw6U6tdfYky8DoJ5Ci2wy",
			"vDAoBgNVHREEITAfggh2Y3NhLTAxYYITdmNzYS0wMWEuY29ycC5sb2NhbDAfBgNV",
			"HSMEGDAWgBRx8PxBR1rBC+LKm0EWXoQulDcqYjA8BggrBgEFBQcBAQQwMC4wLAYI",
			"KwYBBQUHMAKGIGh0dHA6Ly9ib2d1cy5jb20vY2EvbXljb3JwQ0EuY3J0MDEGA1Ud",
			"HwQqMCgwJqAkoCKGIGh0dHA6Ly9ib2d1cy5jb20vY2EvbXljb3JwQ0EuY3JsMA0G",
			"CSqGSIb3DQEBCwUAA4ICAQAEA0NFWu5aLpzUgcGiNKIXsPXpXPWfHQaQ0Q2KWAPI",
			"keEcpOVMcA4NFfxDnFYPzs1VoMvsqRe9RKgko9hYCSeJSryJQsn9I0d3etSa6wDD",
			"8KiwUdT7gnNsswzAZkct9s08sRKh0IZWybmI8cClQDlZgrRIY/RLnfhoftkjGRh2",
			"bmqfHf+2mwBO+0Nk4ZpSyEqW4uuu5FoyamAeqYDjb8kMUbE5IPica/99rlr0iPVU",
			"Dxnfrd8gwMGvGWoEfkKOPYdfrW4CrGvYH44ynoA8Q0RyeVNYwzOZkRHRYA40ynjz",
			"OZ5Jqq0FcpXwDlp7Lkv/T7dMWJIBwfsmWvyvIUtvon3OzSUKyh3BYqtxiaYwUMk+",
			"09O5Iy07do8Pngo8s0rR0KHDH5TighMtmsCHwWVkvrW7dl7cTKlw9B8rO+JEiLJy",
			"1zuxCiY8AUvSwke7vlV4LlU737b0Bz0R1rleXALelbp0kyaR8/sPIsQuu9VLmY3G",
			"iL6EkTmtZrkdAXCmEqGu03eB1JJgEpdR4zukRt64vvIa/YtRd5Z16SepDDBFSbfT",
			"zCS7+E1yCiWQj69/sZY8U3JuqBq0xg4j/04Hkanr9Yef/kKCNOhWnbXhYLo/04s8",
			"gJEgvj6BjB6FmYLc0RgTLi521OmwvByONKi1+sZv/ZT2I5VYGSMleYOHcemwqz1y",
			"Zw==",
			"-----END CERTIFICATE-----");
	public static final String vcsa_01aCertDos = String.join("\r\n",
			"-----BEGIN CERTIFICATE-----",
			"MIIFnTCCA4WgAwIBAgIBAzANBgkqhkiG9w0BAQsFADCBjzELMAkGA1UEBhMCVVMx",
			"EzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xEzAR",
			"BgNVBAoMCkJvZ3VzIEluYy4xEzARBgNVBAsMCk9wZXJhdGlvbnMxKTAnBgNVBAMM",
			"IEJvZ3VzIEluYy4gQ2VydGlmaWNhdGUgQXV0aG9yaXR5MB4XDTE3MDgyNDAzNTM0",
			"N1oXDTE5MDgyNDAzNTM0N1owdzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlm",
			"b3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xEzARBgNVBAoMCkJvZ3VzIElu",
			"Yy4xEzARBgNVBAsMCk9wZXJhdGlvbnMxETAPBgNVBAMMCHZjc2EtMDFhMIIBIjAN",
			"BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz3WgSFUJjKEc7P7VfnsHounTpE69",
			"qzovgejlV7nIFjnNYnMAzG9kSNbob/cHhgcw8qGVR+zWyxfpZVe2KEy/Oryhs4kZ",
			"2P5sJRJOOVVIoZ/FLXbBb44FTKsoiqBInh0KrJkQm/1yh+vpkORlN8dQZPdQiA++",
			"mt1d7xNWfXqDCmm+1uYl+zhsXSz16CmIXXs1m02vpKtAoMBjpC/3UiHVSni6XYSO",
			"gaBT5pdqZ6z52sXvIvfcaJcxMtBGiLp1Y3IIbQuN6HCr8H+jM+Qhx4jtvkt8/wva",
			"1CoVbB1132+yFD72isv6hoZ7/Tfpdk4AjdhuQLrP44KQyaJnbtRC1M5fSwIDAQAB",
			"o4IBGTCCARUwDgYDVR0PAQH/BAQDAgWgMAkGA1UdEwQCMAAwHQYDVR0lBBYwFAYI",
			"KwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBQeF8RXw6U6tdfYky8DoJ5Ci2wy",
			"vDAoBgNVHREEITAfggh2Y3NhLTAxYYITdmNzYS0wMWEuY29ycC5sb2NhbDAfBgNV",
			"HSMEGDAWgBRx8PxBR1rBC+LKm0EWXoQulDcqYjA8BggrBgEFBQcBAQQwMC4wLAYI",
			"KwYBBQUHMAKGIGh0dHA6Ly9ib2d1cy5jb20vY2EvbXljb3JwQ0EuY3J0MDEGA1Ud",
			"HwQqMCgwJqAkoCKGIGh0dHA6Ly9ib2d1cy5jb20vY2EvbXljb3JwQ0EuY3JsMA0G",
			"CSqGSIb3DQEBCwUAA4ICAQAEA0NFWu5aLpzUgcGiNKIXsPXpXPWfHQaQ0Q2KWAPI",
			"keEcpOVMcA4NFfxDnFYPzs1VoMvsqRe9RKgko9hYCSeJSryJQsn9I0d3etSa6wDD",
			"8KiwUdT7gnNsswzAZkct9s08sRKh0IZWybmI8cClQDlZgrRIY/RLnfhoftkjGRh2",
			"bmqfHf+2mwBO+0Nk4ZpSyEqW4uuu5FoyamAeqYDjb8kMUbE5IPica/99rlr0iPVU",
			"Dxnfrd8gwMGvGWoEfkKOPYdfrW4CrGvYH44ynoA8Q0RyeVNYwzOZkRHRYA40ynjz",
			"OZ5Jqq0FcpXwDlp7Lkv/T7dMWJIBwfsmWvyvIUtvon3OzSUKyh3BYqtxiaYwUMk+",
			"09O5Iy07do8Pngo8s0rR0KHDH5TighMtmsCHwWVkvrW7dl7cTKlw9B8rO+JEiLJy",
			"1zuxCiY8AUvSwke7vlV4LlU737b0Bz0R1rleXALelbp0kyaR8/sPIsQuu9VLmY3G",
			"iL6EkTmtZrkdAXCmEqGu03eB1JJgEpdR4zukRt64vvIa/YtRd5Z16SepDDBFSbfT",
			"zCS7+E1yCiWQj69/sZY8U3JuqBq0xg4j/04Hkanr9Yef/kKCNOhWnbXhYLo/04s8",
			"gJEgvj6BjB6FmYLc0RgTLi521OmwvByONKi1+sZv/ZT2I5VYGSMleYOHcemwqz1y",
			"Zw==",
			"-----END CERTIFICATE-----");
	public static final String vcsa_01aCertSha1Thumb = "83:DB:41:DB:AC:BB:E4:F0:1C:00:07:53:23:17:01:6A:DF:64:82:A1";
	public static final String vcsa_01aCertSha256Thumb = "0C:A2:8E:86:4D:DD:C4:BC:29:3B:22:E7:15:B3:28:4D:3F:D0:13:E8:F6:4B:33:7C:78:A8:20:F8:14:F3:EC:94";
	public static final String vcsa_01aPrivateKey = String.join("\n",
			"-----BEGIN PRIVATE KEY-----",
			"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDPdaBIVQmMoRzs",
			"/tV+ewei6dOkTr2rOi+B6OVXucgWOc1icwDMb2RI1uhv9weGBzDyoZVH7NbLF+ll",
			"V7YoTL86vKGziRnY/mwlEk45VUihn8UtdsFvjgVMqyiKoEieHQqsmRCb/XKH6+mQ",
			"5GU3x1Bk91CID76a3V3vE1Z9eoMKab7W5iX7OGxdLPXoKYhdezWbTa+kq0CgwGOk",
			"L/dSIdVKeLpdhI6BoFPml2pnrPnaxe8i99xolzEy0EaIunVjcghtC43ocKvwf6Mz",
			"5CHHiO2+S3z/C9rUKhVsHXXfb7IUPvaKy/qGhnv9N+l2TgCN2G5Aus/jgpDJomdu",
			"1ELUzl9LAgMBAAECggEAPp+sNYlt64SK3cODIL30rSnWWEfomzJiOt3ZtSSAkKz8",
			"IZbDi/KoHBC7c2jnXX74OJWsIV0N7ZqXOp9CfmHEa++bBD4Djmwmqv4enNHwrdEz",
			"zSiG9ayyTtVv1IDTyt7LZRSDXgMguoTtKW64WyEQVJoPNjNCfy8JduyodBIyUkbT",
			"rkHW4m42JkG0UPuu45fg3bXhf0tyx6MwDzVyhbWvrJVSM1352gmd+4R4K4OM+0px",
			"/VkrRUaTRey6hpxyPBXMNV31MXnFufaFbQFgiHQg8w3/8KUAK9gb6y+gHl8AWEKF",
			"0Uym0Jy6OGEzKDjcucba8dkmOQ+RD6wJpzA7r5oOqQKBgQD9n3Ygn0t9GAryyil9",
			"fb2zhbYeO9d3mcqPTHS6BUfuxiEaGVcxFNuDjwPSTymp5P5OK44w6Sgm+lVpjBZI",
			"CJTnvmvHSHzmADHE02Nx8gdLkC2wNokP1t5pNf5jFrvBK9J6YeenCIcRoovmoM2O",
			"EYL4JOA+OGIpofkwmHhZCLtBvwKBgQDRZ2ajJp9tVFOoNwOTrSVz1E+d3mrdDs11",
			"loL9sjKdacNEYWuUXqG+vczE1LjGkujbKYDGAcWAJypoK2Hl/qMZXmDndkI6bn7r",
			"suJDcoeUtPFwt4VbhdbPnM8zhfRp76VvSU0xlbyAtrzJrweY8wC0kCKRiU2W2aRb",
			"e0yEDIVtdQKBgGzOgIs2S9h6/Bd1C5++1ieycZM+8Q1qeTBJCLrVkSqq7YCY5oM0",
			"A4jJTkZnl+Q/TaqTnQj2vjcappIFe3mj1N4nH237dznlU3Sxi7RStTaBwFgczWhy",
			"MjDI7T3tftc8yaufXRaX3fp+1a43xnfwo1N53opS/ioGRzXF87uet1dZAoGBALto",
			"fB4V6ebx6nEI02WuN2+jmqGiNiejINRVIOSmP9BLoFupiJtf2ggYW5PpAXmOb2H9",
			"keckHLrl0nkqIlKxgwyoP7fHSdx7mZGeJgvRC3BWRCLpzCst7CMgpvvorebFeFzR",
			"0IlJBkx3vxwNTpJfIMl4mceAh3UzUXoiLkeb4SolAoGAaZu+jEnZNYs9E1lwrTpt",
			"gzkwN0CP7ktXTgmJiRU6eC7wEP2XrvwyTExt+D+GgM0ICnBYQLFYd4gyZ001ScOn",
			"slNLfsy9PJBNbXqG8VEliYwoPic+ccfv9+lQVmc9shqhaWAUaSarw75V2PJzOkV3",
			"x9RfR4E5ktFdy1IwYxQAmeg=",
			"-----END PRIVATE KEY-----");
	public static final String vcsa01aPublicKey = String.join("\n",
			"-----BEGIN PUBLIC KEY-----",
			"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz3WgSFUJjKEc7P7VfnsH",
			"ounTpE69qzovgejlV7nIFjnNYnMAzG9kSNbob/cHhgcw8qGVR+zWyxfpZVe2KEy/",
			"Oryhs4kZ2P5sJRJOOVVIoZ/FLXbBb44FTKsoiqBInh0KrJkQm/1yh+vpkORlN8dQ",
			"ZPdQiA++mt1d7xNWfXqDCmm+1uYl+zhsXSz16CmIXXs1m02vpKtAoMBjpC/3UiHV",
			"Sni6XYSOgaBT5pdqZ6z52sXvIvfcaJcxMtBGiLp1Y3IIbQuN6HCr8H+jM+Qhx4jt",
			"vkt8/wva1CoVbB1132+yFD72isv6hoZ7/Tfpdk4AjdhuQLrP44KQyaJnbtRC1M5f",
			"SwIDAQAB",
			"-----END PUBLIC KEY-----");
}