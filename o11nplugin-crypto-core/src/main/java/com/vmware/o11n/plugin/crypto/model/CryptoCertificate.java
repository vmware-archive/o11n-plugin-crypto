/*
 * Copyright (c) 2017 VMware, Inc. All Rights Reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */
package com.vmware.o11n.plugin.crypto.model;

import java.io.Serializable;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Map;

import javax.naming.InvalidNameException;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import com.vmware.o11n.plugin.sdk.annotation.VsoConstructor;
import com.vmware.o11n.plugin.sdk.annotation.VsoMethod;
import com.vmware.o11n.plugin.sdk.annotation.VsoObject;
import com.vmware.o11n.plugin.sdk.annotation.VsoParam;
import com.vmware.o11n.plugin.sdk.annotation.VsoProperty;


@VsoObject(
create=true,
strict=true,
description="A scripting object representing a X.509 certificate")
public class CryptoCertificate implements Serializable, Cloneable {

	@Autowired
	private static CryptoCertificateService service;

	private final Logger log = LoggerFactory.getLogger(CryptoCertificate.class);

	/* Constants */
	private static final long serialVersionUID = 7252197349636955057L;
	public static final String TYPE = "CryptoCertificate";
	private static final String[] EMPTY_STRING_ARRAY = new String[0];

	/* Local write once variables: */
	private final X509Certificate cert;
	private final String certString;  //PEM encoded certificate


	@VsoConstructor(description="A X.509 Certificate Object")
	public CryptoCertificate(@VsoParam(description="PEM encoded certificate") String certString) {
		if (service == null) {
			service = new CryptoCertificateService();
		}
		try {
			this.cert = service.parseCertificate(certString);
			this.certString = CryptoUtil.pemEncode(this.cert);
		} catch (CertificateException ce) {
			throw new IllegalArgumentException("Invalid certificate");
		}
	}

	public CryptoCertificate(X509Certificate cert) throws CertificateEncodingException {
		if (service == null) {
			service = new CryptoCertificateService();
		}
		this.cert = cert;
		this.certString = CryptoUtil.pemEncode(cert);
	}


	/**
	 *
	 * @return
	 */
	@VsoProperty(name="sha1Fingerprint",
			description="SHA1 fingerprint of the certificate")
	public String getSha1Fingerprint() {
		String toReturn = null;
		try {
			toReturn = service.getSha1Fingerprint(this.cert);
		} catch (CertificateException ce) {
			log.error(ce.getMessage());
		} catch (Throwable e) {
			log.error("Unexpected exception: "+e.getMessage());
		}
		return toReturn;
	}

	/**
	 *
	 * @return
	 */
	@VsoProperty(name="sha256Fingerprint",
			description="SHA256 fingerprint of the certificate")
	public String getSha256Fingerprint() {
		String toReturn = null;
		try {
			toReturn = service.getSha256Fingerprint(this.cert);
		} catch (CertificateException ce) {
			log.error(ce.getMessage());
		} catch (Throwable e) {
			log.error("Unexpected exception: "+e.getMessage());
		}
		return toReturn;
	}

	/**
	 *
	 * @return
	 */
	@VsoProperty(name="encodedBase64",
			description="Encoded form of the certificate encoded as a Base64 string.  Hashing this can create a fingerprint")
	public String getEncodedBase64() {
		String toReturn = null;
		try {
			toReturn = service.getEncodedBase64(this.cert);
		} catch (CertificateException ce) {
			log.error(ce.getMessage());
		} catch (Throwable e) {
			log.error("Unexpected exception: "+e.getMessage());
		}
		return toReturn;
	}
	/**
	 *
	 * @return
	 */
	@VsoProperty(name="pemEncoded",
			description="PEM Encodinf of the certificate")
	public String getPemEncoded() {
		return this.certString;
	}

	/**
	 *
	 * @return
	 */
	@VsoProperty(name="publicKeyPem",
			description="The RSA Public Key in PEM format found in the certificate")
	public String getPublicKeyPem() {
		return service.getPublicKeyPem(this.cert);
	}

	/**
	 *
	 * @return
	 */
	@VsoProperty(name="subjectAlternativeNames",
			description="A list of DNS subject alternative names found in the certificate")
	public String[] getSubjectAlternativeNames() {
		try {
			List<String> san = service.getSubjectAlternativeNames(this.cert);
			if (san != null && san.size() > 0) {
				return san.toArray(EMPTY_STRING_ARRAY);
			}
		} catch (CertificateParsingException e) {
			log.error(e.toString());
		}
		return EMPTY_STRING_ARRAY;
	}

	/**
	 *
	 * @return
	 */
	@VsoProperty(name="signatureAlgorithm")
	public String getSignatureAlgorithm() {
		return this.cert.getSigAlgName();
	}

	/**
	 *
	 * @return
	 */
	@VsoProperty(name="signatureBase64")
	public String getSignatureBase64 () {
		byte[] sig = this.cert.getSignature();
		return Base64.encodeBase64String(sig);
	}

	/**
	 *
	 * @return
	 */
	@VsoProperty(name="serialNumber")
	public String getSerialNumber() {
		return service.getSerialNumber(this.cert);
	}

	/**
	 *
	 * @return
	 */
	@VsoProperty(name="issuedToDN")
	public String getIssuedToDN() {
		return this.cert.getSubjectDN().getName();
	}

	/**
	 *
	 * @return
	 * @throws InvalidNameException
	 */
	@VsoProperty(name="issuedToMap")
	public Map<String,String> getIssuedToMap() throws InvalidNameException {
		return service.parseDN(this.getIssuedToDN());
	}

	/**
	 *
	 * @return
	 */
	@VsoProperty(name="issuedByDN")
	public String getIssuedByDN() {
		return this.cert.getIssuerDN().getName();
	}

	/**
	 *
	 * @return
	 * @throws InvalidNameException
	 */
	@VsoProperty(name="issuedByMap")
	public Map<String,String> getIssuedByMap() throws InvalidNameException {
		return service.parseDN(this.getIssuedByDN());
	}

	/**
	 *
	 * @return
	 */
	@VsoMethod(vsoReturnType="Date",
			description="The certificate is valid before this date")
	public Date getValidBefore() {
		return this.cert.getNotAfter();
	}

	/**
	 *
	 * @return
	 */
	@VsoMethod(vsoReturnType="Date",
			description="The certificate is valid after this date")
	public Date getValidAfter() {
		return this.cert.getNotBefore();
	}

	/**
	 *
	 * @param date
	 * @return
	 */
	@VsoMethod(vsoReturnType="boolean",
			description="Is the certificate valid based on a provided date")
	public boolean isValidOn( @VsoParam(vsoType="Date",description="Date to check certificate validity on") Date date) {
		final Date validAfter = this.cert.getNotBefore();
		final Date validBefore = this.cert.getNotAfter();

		if (validAfter.compareTo(date) > 0) { //'validAfter' is after date
			//certificate is not valid yet compared to this date
			return false;
		}
		if (validBefore.compareTo(date) < 0) { // 'validBefore is before date'
			//certificate is expired compared to this date
			return false;
		}
		// passing both these checks, the cert is valid for this date
		return true;
	}
}
