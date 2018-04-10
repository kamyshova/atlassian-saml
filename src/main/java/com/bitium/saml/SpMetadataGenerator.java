package com.bitium.saml;

import com.bitium.saml.config.SAMLConfig;
import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.FileSystemResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import org.springframework.security.saml.metadata.MetadataGenerator;

import javax.servlet.ServletException;
import java.io.File;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class SpMetadataGenerator {

    private final String keyStorePass = "changeit";
    private final String keyAlias = "pipe-cert";
    private final String signingKey = "api-saml-cert";

	public MetadataProvider generate(SAMLConfig configuration) throws ServletException, MetadataProviderException {
	
        MetadataGenerator generator = new MetadataGenerator();

        // Defaults
        String baseURL = configuration.getBaseUrl();

        generator.setEntityBaseURL(baseURL);
        generator.setEntityId("http://localhost:1990/confluence/");

        // Use default entityID if not set
        if (generator.getEntityId() == null) {
            generator.setEntityId(configuration.getSpEntityId());
        }

        generator.setBindingsSSO(Collections.singletonList("post"));
        generator.setKeyManager(keyManager());

        ExtendedMetadata extendedMetadata = extendedMetadata();
        generator.setExtendedMetadata(extendedMetadata);

        return extendedMetadataDelegate();
	}

    public KeyManager keyManager() {
        DefaultResourceLoader loader = new FileSystemResourceLoader();
        Resource storeFile = loader.getResource("file:/home/yulia_kamyshova/api/sso/devKeystore.jks");
        String storePass = keyStorePass;
        Map<String, String> passwords = new HashMap<String, String>();
        passwords.put(keyAlias, keyStorePass);
        passwords.put(signingKey, keyStorePass);
        String defaultKey = keyAlias;
        return new JKSKeyManager(storeFile, storePass, passwords, defaultKey);
    }

    public ExtendedMetadata extendedMetadata() {
        ExtendedMetadata extendedMetadata = new ExtendedMetadata();
        extendedMetadata.setIdpDiscoveryEnabled(true);
        extendedMetadata.setSignMetadata(true);
        return extendedMetadata;
    }

    public ExtendedMetadataDelegate extendedMetadataDelegate() {
        try {
            FilesystemMetadataProvider metadataProvider =
                    new FilesystemMetadataProvider(new File("/home/yulia_kamyshova/api/sso/FederationMetadata.xml"));
            metadataProvider.setParserPool(org.opensaml.Configuration.getParserPool());
            metadataProvider.initialize();
            return new ExtendedMetadataDelegate(metadataProvider, extendedMetadata());
        } catch (MetadataProviderException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
