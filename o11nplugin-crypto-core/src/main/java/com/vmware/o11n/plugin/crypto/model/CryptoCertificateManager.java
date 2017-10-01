/*
 * Copyright (c) 2017 VMware, Inc. All Rights Reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */
package com.vmware.o11n.plugin.crypto.model;

import java.io.IOException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import com.vmware.o11n.plugin.crypto.service.CryptoCertificateService;
import com.vmware.o11n.plugin.sdk.annotation.VsoMethod;
import com.vmware.o11n.plugin.sdk.annotation.VsoObject;
import com.vmware.o11n.plugin.sdk.spring.AbstractSpringPluginFactory;

import ch.dunes.vso.sdk.api.IPluginFactory;

@VsoObject(
create=false,
strict=true,
singleton=true,
description="Provides methods to parse or fetch certificates")
public class CryptoCertificateManager {
	private final Logger log = LoggerFactory.getLogger(CryptoCertificateManager.class);

	@Autowired
	private CryptoCertificateService service;

	public static CryptoCertificateManager createScriptingSingleton(IPluginFactory factory) {
		return ((AbstractSpringPluginFactory) factory).createScriptingObject(CryptoCertificateManager.class);
	}

	@VsoMethod(description="parses a PEM encoded X.509 Certificate")
	public CryptoCertificate parseCertificatePem(String pemCertString) throws CertificateException {
		X509Certificate cert = service.parseCertificate(pemCertString);
		return new CryptoCertificate(cert);
	}

	@VsoMethod(description="Returns array of certificates presented by an https server")
	public CryptoCertificate[] getHttpsCertificate(String urlString) throws KeyManagementException, NoSuchAlgorithmException, IOException, CertificateEncodingException {
		ArrayList<CryptoCertificate> toReturn = new ArrayList<>();
		URL url = new URL(urlString);
		List<X509Certificate> certs = service.getCertHttps(url);
		if (log.isDebugEnabled() && certs != null){
			log.debug("Number of certs found at url: "+certs.size());
		}
		for (X509Certificate cert : certs) {
			toReturn.add(new CryptoCertificate(cert));
		}
		return toReturn.toArray(new CryptoCertificate[toReturn.size()]);
	}
}
