package com.bitium.saml;

import com.bitium.saml.config.SAMLConfig;
import java.io.File;
import org.junit.Test;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import static junit.framework.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class MetadataInitialisationTest {
    @Test
    public void logoutUrlRetrievingTest() throws ConfigurationException {
        DefaultBootstrap.bootstrap();

        final SAMLConfig config = new SAMLConfig();
        config.setMetadataFile(new File("src/test/resources/test-metadata.xml"));

        assertEquals("logoutUrl", config.getLogoutUrl());
    }
}
