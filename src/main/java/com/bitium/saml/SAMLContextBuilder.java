package com.bitium.saml;

import com.bitium.saml.config.SAMLConfig;
import org.opensaml.Configuration;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.security.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xml.security.x509.X509KeyInfoGeneratorFactory;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.FileSystemResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.security.saml.SAMLConstants;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.metadata.MetadataMemoryProvider;

import javax.servlet.ServletException;
import java.io.File;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class SAMLContextBuilder {


    static {
        NamedKeyInfoGeneratorManager manager = Configuration.getGlobalSecurityConfiguration().getKeyInfoGeneratorManager();
        X509KeyInfoGeneratorFactory generator = new X509KeyInfoGeneratorFactory();
        generator.setEmitEntityCertificate(true);
        generator.setEmitEntityCertificateChain(true);
        manager.registerFactory(SAMLConstants.SAML_METADATA_KEY_INFO_GENERATOR, generator);
    }

    private SAMLConfig configuration;

    public SAMLContextBuilder(SAMLConfig samlConfig) {
        this.configuration = samlConfig;
    }

    public SAMLContext buildContext() throws MetadataProviderException, ServletException {
        KeyManager keyManager = initKeyManager(configuration.getKeystore(), configuration.getKeyStorePasswordSetting(),
                configuration.getSignKeySetting());

        MetadataManager metadataManager =
                initMetadataManager(configuration.getBaseUrl(),
                        configuration.getSpEntityId(), configuration.getIdpMetadataFile(),
                        configuration.getSignKeySetting(), keyManager);

        SAMLContextProvider contextProvider = initContextProvider(metadataManager, keyManager);

        return new SAMLContext(metadataManager, contextProvider, configuration.getRequestBindingSetting(),
                configuration.getMaxAuthenticationAge());
    }

    private SAMLContextProvider initContextProvider(MetadataManager metadataManager, KeyManager keyManager) throws ServletException {
        SAMLContextProviderImpl contextProvider = new SAMLContextProviderImpl();
        contextProvider.setMetadata(metadataManager);
        contextProvider.setKeyManager(keyManager);
        contextProvider.afterPropertiesSet();
        return contextProvider;
    }

    private MetadataManager initMetadataManager(String baseUrl, String spEntityId, String idpMetadataFile,
                                                String signingKey, KeyManager keyManager)
            throws MetadataProviderException {

        MetadataGenerator spMetadataGenerator = initMetadataGenerator(baseUrl, spEntityId, keyManager);

        EntityDescriptor entityDescriptor = spMetadataGenerator.generateMetadata();
        ExtendedMetadata extendedMetadata = spMetadataGenerator.generateExtendedMetadata();
        extendedMetadata.setSigningKey(signingKey);

        MetadataMemoryProvider metadataMemoryProvider = new MetadataMemoryProvider(entityDescriptor);
        metadataMemoryProvider.initialize();

        MetadataProvider spMetadataProvider = new ExtendedMetadataDelegate(metadataMemoryProvider, extendedMetadata);

        MetadataProvider idpMetadataProvider = extendedMetadataDelegate(idpMetadataFile);

        MetadataManager metadataManager = new MetadataManager(Arrays.asList(spMetadataProvider, idpMetadataProvider));
        metadataManager.setKeyManager(keyManager);
        metadataManager.setHostedSPName(spEntityId);
        metadataManager.refreshMetadata();
        return metadataManager;
    }


    private MetadataGenerator initMetadataGenerator(String baseUrl, String spEntityId, KeyManager keyManager) {
        MetadataGenerator generator = new MetadataGenerator();
        generator.setEntityBaseURL(baseUrl);
        // Use default entityID if not set
        if (generator.getEntityId() == null) {
            generator.setEntityId(spEntityId);
        }
        generator.setBindingsSSO(Collections.singletonList("post"));
        generator.setKeyManager(keyManager);
        generator.setExtendedMetadata(initExtendedMetadata());
        return generator;
    }

    private KeyManager initKeyManager(String keystorePath, String keystorePassword, String signKey) {
        DefaultResourceLoader loader = new FileSystemResourceLoader();
        Resource storeFile = loader.getResource(keystorePath);
        Map<String, String> passwords = new HashMap<String, String>();
        passwords.put(signKey, keystorePassword);
        return new JKSKeyManager(storeFile, keystorePassword, passwords, signKey);
    }

    private ExtendedMetadata initExtendedMetadata() {
        ExtendedMetadata extendedMetadata = new ExtendedMetadata();
        extendedMetadata.setIdpDiscoveryEnabled(true);
        extendedMetadata.setSignMetadata(true);
        return extendedMetadata;
    }

    private ExtendedMetadataDelegate extendedMetadataDelegate(String idpMetadataFile) {
        try {
            FilesystemMetadataProvider metadataProvider =
                    new FilesystemMetadataProvider(new File(idpMetadataFile));
            metadataProvider.setParserPool(org.opensaml.Configuration.getParserPool());
            metadataProvider.initialize();
            return new ExtendedMetadataDelegate(metadataProvider, initExtendedMetadata());
        } catch (MetadataProviderException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
