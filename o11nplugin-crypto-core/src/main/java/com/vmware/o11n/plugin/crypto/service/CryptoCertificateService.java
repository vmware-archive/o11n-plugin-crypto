/*
 * Copyright (c) 2017 VMware, Inc. All Rights Reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */
package com.vmware.o11n.plugin.crypto.service;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.vmware.o11n.plugin.crypto.model.CryptoUtil;

@Component
public class CryptoCertificateService {

	private final Logger log = LoggerFactory.getLogger(CryptoCertificateService.class);

	/**
	 *
	 *
	 */
	private static final Map<Integer,String> sanType;
	static {
		sanType = new HashMap<>();
		sanType.put(0, "Other");
		sanType.put(1, "rfc822Name");
		sanType.put(2, "DNS");
		sanType.put(3, "x400Address");
		sanType.put(4, "directoryName");
		sanType.put(5, "ediPartyName");
		sanType.put(6, "uniformResourceIdentifier");
		sanType.put(7, "ipAddress");
		sanType.put(8, "registeredID");
	}


	/**
	 * Get SHA1 fingerprint/thumbprint of a Certificate
	 * Returns the fingerprint as a colon delimited hex string
	 *
	 * @param certString PEM encoded certificate
	 * @return Hex encoded sha1 fingerprint of certificate
	 * @throws CertificateException
	 */
	public String getSha1Fingerprint(String certString) throws CertificateException {
		Certificate cert = parseCertificate(certString);
		return getSha1Fingerprint(cert);
	}

	/**
	 * Get SHA1 fingerprint/thumbprint of a Certificate
	 * Returns the fingerprint as a colon delimited hex string
	 *
	 * @param cert Certificate
	 * @return Hex encoded sha1 fingerprint of certificate
	 * @throws CertificateException
	 */
	public String getSha1Fingerprint(Certificate cert) throws CertificateException {
		byte[] encoded = cert.getEncoded();
		String certFinger = DigestUtils.sha1Hex(encoded);
		return fixFingerprintHex(certFinger);
	}

	/**
	 * Get SHA256 fingerprint/thumbprint of a Certificate
	 * Returns the fingerprint as a colon delimited hex string
	 *
	 * @param certString PEM encoded certificate
	 * @return Hex encoded sha256 fingerprint of certificate
	 * @throws CertificateException
	 */
	public String getSha256Fingerprint(String certString) throws CertificateException {
		Certificate cert = parseCertificate(certString);
		return getSha256Fingerprint(cert);
	}

	/**
	 * Get SHA256 fingerprint/thumbprint of a Certificate
	 * Returns the fingerprint as a colon delimited hex string
	 *
	 * @param cert Certificate
	 * @return Hex encoded sha256 fingerprint of certificate
	 * @throws CertificateException
	 */
	public String getSha256Fingerprint(Certificate cert) throws CertificateException {
		byte[] encoded = cert.getEncoded();
		String certFinger = DigestUtils.sha256Hex(encoded);
		return fixFingerprintHex(certFinger);
	}

	/**
	 *
	 * @param cert
	 * @return
	 * @throws CertificateEncodingException
	 */
	public String getEncodedBase64(Certificate cert) throws CertificateEncodingException {
		byte[] encoded = cert.getEncoded();
		return Base64.encodeBase64String(encoded);
	}

	/**
	 * Get the RSA Public key from a X.509 certificate

	 * @param cert Certificate
	 * @return PEM encoded public key
	 */
	public String getPublicKeyPem(Certificate cert) {
		PublicKey pubKey = cert.getPublicKey();
		return CryptoUtil.pemEncode(pubKey);
	}

	/**
	 *
	 * @param cert
	 * @return
	 */
	public String getSerialNumber(X509Certificate cert) {
		String toReturn = "0"+cert.getSerialNumber().toString(16);
		return fixFingerprintHex(toReturn);
	}

	/**
	 *
	 * @param cert
	 * @return
	 * @throws CertificateParsingException
	 */

	public List<String> getSubjectAlternativeNames(X509Certificate cert) throws CertificateParsingException {
		ArrayList<String> toReturn = new ArrayList<>();
		Collection<List<?>> sans = cert.getSubjectAlternativeNames();
		if (sans != null) {
			if  (log.isDebugEnabled()) {
				log.debug("Subject Alternative Names: "+sans.toString());
			}
			for(List<?> l : sans) {
				if (l.size() == 2) {
					Integer type = (Integer)l.get(0);
					if (type.equals(new Integer(2))) {
						//DNS SAN
						String value = (String)l.get(1);
						toReturn.add("dns:"+value);
					} else {
						String message = "SAN type '"+sanType.get(type)+"' not implemented";
						log.warn(message);
					}
				} else {
					log.error("expected subject alternatives names object to have only 2 elements but "+l.size()+" elements were present");
				}
			}
		} else if (log.isDebugEnabled()) {
			log.debug("Empty Subject Alternative Names");
		}
		return toReturn;
	}

	/**
	 * Parses a X.509 certificate from a PEM certificate string
	 *
	 * @param certString
	 * @return
	 * @throws CertificateException
	 */
	public X509Certificate parseCertificate(String certString) throws CertificateException {
		CertificateFactory fac = CertificateFactory.getInstance("X.509");
		ByteArrayInputStream stream = new ByteArrayInputStream(certString.getBytes());
		Certificate cert = fac.generateCertificate(stream);
		if (cert instanceof X509Certificate) {
			return (X509Certificate)cert;
		} else {
			throw new IllegalArgumentException("Provided certificate did not parse as a X509 certificate");
		}
	}


	/**
	 *
	 * @param cert
	 * @param pubKey
	 * @return
	 */
	public boolean verifyCert(Certificate cert, PublicKey pubKey) {
		try {
			cert.verify(pubKey);
		} catch (Throwable t) {
			return false;
		}
		return true;
	}
	/**
	 *
	 * @param cert
	 * @param pubKey
	 * @return
	 * @throws IOException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchAlgorithmException
	 */
	public boolean verifyCert(Certificate cert, String  keyPem) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		PublicKey key = CryptoUtil.getPublicKey(keyPem);
		return verifyCert(cert,key);
	}

	/**
	 * Returns the certificate chain provided by the HTTPS server.
	 *
	 * The first certificate identifies the server.
	 * The remainder should verify the cert upto a trusted root.
	 *
	 *
	 * @param url
	 * @return
	 * @throws IOException
	 * @throws KeyManagementException
	 * @throws NoSuchAlgorithmException
	 */
	public List<X509Certificate> getCertHttps(URL url) throws IOException, KeyManagementException, NoSuchAlgorithmException {
		ArrayList<X509Certificate> toReturn = new ArrayList<>();

		// Setup a temp ssl context that accepts all certificates for this connection
		SSLContext sslContext = SSLContext.getInstance("TLS");
		sslContext.init(null, new TrustManager[]{
				new X509TrustManager() {
				private X509Certificate[] certToReturn;
				@Override
				public void checkClientTrusted(X509Certificate[] c, String s) {}
				@Override
				public void checkServerTrusted(X509Certificate[] c, String s) {
					certToReturn = c;
				}
				@Override
				public X509Certificate[] getAcceptedIssuers() {
					return certToReturn;
				}
			}
		},null);

		//Setup a temp hostname verifier that verifies all hostnames for this connection
		HostnameVerifier hv = new HostnameVerifier() {
			@Override
			public boolean verify(String s, SSLSession ss) {
				return true;
			}
		};
		HttpsURLConnection httpsConn = null;
		try {
			httpsConn = (HttpsURLConnection)url.openConnection();

			httpsConn.setSSLSocketFactory(sslContext.getSocketFactory());
			httpsConn.setHostnameVerifier(hv);
			httpsConn.connect();

			Certificate[] certs = httpsConn.getServerCertificates();

			for (Certificate cert : certs) {
				if (cert instanceof X509Certificate) {
					toReturn.add((X509Certificate)cert);
				}
			}
		} finally {
			if (httpsConn != null) {
				httpsConn.disconnect();
			}
		}
		return toReturn;
	}

	public Map<String,String> parseDN(String dnString) throws InvalidNameException {
		Map<String,String> toReturn = new HashMap<>();
		LdapName ldapName = new LdapName(dnString);
		if (log.isDebugEnabled()) {
			log.debug("Parsing DN: "+dnString);
			log.debug("ldapNames size:"+ldapName.size());
		}
		for (Rdn rdn : ldapName.getRdns()) {
			if (rdn.getValue() instanceof String) {
				if (log.isDebugEnabled()) {
					log.debug("RDN: '"+rdn.getType() +"' has a String value");
				}
				toReturn.put(rdn.getType(), (String)rdn.getValue());
			} else if (rdn.getValue() instanceof byte[] ){
				if (log.isDebugEnabled()) {
					log.debug("RDN: '"+rdn.getType() +"' has a binary value");
				}
				toReturn.put(rdn.getType(), new String((byte[])rdn.getValue()));
			}
		}
		return toReturn;
	}


	/**
	 * Adds ':' delimiters of the Hex bytes traditionally seen with a certificate fingerprint
	 *
	 * @param fingerString un-delimited hex string
	 * @return ':' delimited hex string
	 */
	private String fixFingerprintHex(String fingerString) {
		return fingerString.toUpperCase().replaceAll("(?<=..)(..)", ":$1");
	}
}
