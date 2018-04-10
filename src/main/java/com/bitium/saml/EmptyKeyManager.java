package com.bitium.saml;

import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.credential.Credential;
import org.springframework.security.saml.key.KeyManager;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Set;

public class EmptyKeyManager implements KeyManager {

	public Iterable<Credential> resolve(CriteriaSet arg0)
			throws SecurityException {
		return null;
	}

	public Credential resolveSingle(CriteriaSet arg0) throws SecurityException {
		return null;
	}

	public Credential getCredential(String keyName) {
		return null;
	}

	public Credential getDefaultCredential() {
		return null;
	}

	public String getDefaultCredentialName() {
		return null;
	}

	@SuppressWarnings("unchecked")
	public Set<String> getAvailableCredentials() {
		return Collections.EMPTY_SET;
	}

	public X509Certificate getCertificate(String alias) {
		return null;
	}
}
