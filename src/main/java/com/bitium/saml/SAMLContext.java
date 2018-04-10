package com.bitium.saml;

import com.bitium.saml.config.SAMLConfig;
import org.apache.commons.httpclient.HttpClient;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.Configuration;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.util.resource.ResourceException;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.security.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xml.security.x509.X509KeyInfoGeneratorFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.security.saml.SAMLConstants;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.*;
import org.springframework.security.saml.processor.*;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.saml.websso.ArtifactResolutionProfile;
import org.springframework.security.saml.websso.ArtifactResolutionProfileImpl;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.UnsupportedEncodingException;
import java.security.cert.CertificateException;
import java.util.*;

public class SAMLContext {
	private static final Logger logger = LoggerFactory.getLogger(SAMLContext.class);
	private static final SAMLProcessor samlProcessor;
	
	private MetadataManager metadataManager;
	private KeyManager idpKeyManager;
	private KeyManager spKeyManager;
	private SAMLMessageContext samlMessageContext;
	private MetadataGenerator spMetadataGenerator;
	private SAMLContextProviderImpl messageContextProvider;

	static {
		Collection<SAMLBinding> bindings = new ArrayList<SAMLBinding>();
		bindings.add(httpRedirectDeflateBinding());
		bindings.add(httpPostBinding());
		bindings.add(artifactBinding(Configuration.getParserPool(), velocityEngine()));
		bindings.add(httpSOAP11Binding());
		bindings.add(httpPAOS11Binding());

        samlProcessor = new SAMLProcessorImpl(bindings);
	}

	public static HTTPRedirectDeflateBinding httpRedirectDeflateBinding() {
		return new HTTPRedirectDeflateBinding(Configuration.getParserPool());
	}

	public static HTTPSOAP11Binding httpSOAP11Binding() {
		return new HTTPSOAP11Binding(Configuration.getParserPool());
	}

	public static HTTPPAOS11Binding httpPAOS11Binding() {
		return new HTTPPAOS11Binding(Configuration.getParserPool());
	}

	public static HTTPArtifactBinding artifactBinding(ParserPool parserPool, VelocityEngine velocityEngine) {
		return new HTTPArtifactBinding(parserPool, velocityEngine, artifactResolutionProfile());
	}

	public SAMLContext(HttpServletRequest request, SAMLConfig configuration) throws ConfigurationException, CertificateException, UnsupportedEncodingException, MetadataProviderException, ServletException, ResourceException {
		setMetadataKeyInfoGenerator();

		configuration.setDefaultBaseUrl(getDefaultBaseURL(request));

		spMetadataGenerator = metadataGenerator(configuration);

		EntityDescriptor entityDescriptor = spMetadataGenerator.generateMetadata();
		ExtendedMetadata extendedMetadata = spMetadataGenerator.generateExtendedMetadata();

		MetadataMemoryProvider metadataMemoryProvider = new MetadataMemoryProvider(entityDescriptor);
		metadataMemoryProvider.initialize();

		MetadataProvider spMetadataProvider = new ExtendedMetadataDelegate(metadataMemoryProvider, extendedMetadata);

		MetadataProvider idpMetadataProvider = new ExtendedMetadataDelegate(configuration.getMetadataProvider(), extendedMetadata());
		
		metadataManager = new MetadataManager(Arrays.asList(spMetadataProvider, idpMetadataProvider));
		KeyManager keyManager = generateKeyManager(configuration);
		metadataManager.setKeyManager(keyManager);
		metadataManager.setHostedSPName(configuration.getSpEntityId());
		metadataManager.refreshMetadata();

		messageContextProvider = new SAMLContexProviderCustomSingKey(configuration.getSignKeySetting());
		messageContextProvider.setMetadata(metadataManager);
		messageContextProvider.setKeyManager(keyManager);
		messageContextProvider.afterPropertiesSet();
	}
	
	public SAMLMessageContext createSamlMessageContext(HttpServletRequest request, HttpServletResponse response) throws ServletException, MetadataProviderException {
		samlMessageContext = messageContextProvider.getLocalAndPeerEntity(request, response);
		
		SPSSODescriptor spDescriptor = (SPSSODescriptor) samlMessageContext.getLocalEntityRoleMetadata();
		
		String responseURL = request.getRequestURL().toString();
		spDescriptor.getDefaultAssertionConsumerService().setResponseLocation(responseURL);
		for (AssertionConsumerService service : spDescriptor.getAssertionConsumerServices()) {
			service.setResponseLocation(responseURL);
		}
		
		spDescriptor.setAuthnRequestsSigned(true);
		samlMessageContext.setCommunicationProfileId(SAMLConstants.SAML2_WEBSSO_PROFILE_URI);
		
		return samlMessageContext;
	}

	public SAMLProcessor getSamlProcessor() {
		return samlProcessor;
	}

	public MetadataManager getMetadataManager() {
		return metadataManager;
	}

	public KeyManager getIdpKeyManager() {
		return idpKeyManager;
	}

	private String getDefaultBaseURL(HttpServletRequest request) {
        StringBuilder sb = new StringBuilder();
        sb.append(request.getScheme()).append("://").append(request.getServerName()).append(":").append(request.getServerPort());
        sb.append(request.getContextPath());
        return sb.toString();
    }
	
	private MetadataGenerator metadataGenerator(SAMLConfig configuration) {

		MetadataGenerator generator = new MetadataGenerator();

		// Defaults
		String baseURL = configuration.getBaseUrl();

		generator.setEntityBaseURL(baseURL);

		// Use default entityID if not set
		if (generator.getEntityId() == null) {
			generator.setEntityId(configuration.getSpEntityId());
		}

		generator.setBindingsSSO(Collections.singletonList("post"));
		generator.setKeyManager(generateKeyManager(configuration));

		ExtendedMetadata extendedMetadata = extendedMetadata();
		generator.setExtendedMetadata(extendedMetadata);

		return generator;
	}

	public KeyManager generateKeyManager(SAMLConfig samlConfig) {
		Resource storeFile = samlConfig.getKeystoreFile();
		String keyStorePassword = samlConfig.getKeyStorePasswordSetting();
		Map<String, String> passwords = new HashMap<String, String>();
		String signKey = samlConfig.getSignKeySetting();
		passwords.put(signKey, keyStorePassword);
		spKeyManager = new JKSKeyManager(storeFile, keyStorePassword, passwords, signKey);
		return spKeyManager;
	}

	public ExtendedMetadata extendedMetadata() {
		ExtendedMetadata extendedMetadata = new ExtendedMetadata();
		extendedMetadata.setIdpDiscoveryEnabled(true);
		extendedMetadata.setSignMetadata(true);
		return extendedMetadata;
	}

	protected void setMetadataKeyInfoGenerator() {
		NamedKeyInfoGeneratorManager manager = Configuration.getGlobalSecurityConfiguration().getKeyInfoGeneratorManager();
		X509KeyInfoGeneratorFactory generator = new X509KeyInfoGeneratorFactory();
		generator.setEmitEntityCertificate(true);
		generator.setEmitEntityCertificateChain(true);
		manager.registerFactory(SAMLConstants.SAML_METADATA_KEY_INFO_GENERATOR, generator);
	}


	private static ArtifactResolutionProfile artifactResolutionProfile() {
		final ArtifactResolutionProfileImpl artifactResolutionProfile =
				new ArtifactResolutionProfileImpl(httpClient());
		artifactResolutionProfile.setProcessor(new SAMLProcessorImpl(soapBinding()));
		return artifactResolutionProfile;
	}

	public static HttpClient httpClient() {
		return new HttpClient();
	}

	public static HTTPSOAP11Binding soapBinding() {
		return new HTTPSOAP11Binding(Configuration.getParserPool());
	}

	public static VelocityEngine velocityEngine() {
		return VelocityFactory.getEngine();
	}

	public static HTTPPostBinding httpPostBinding() {
		return new HTTPPostBinding(Configuration.getParserPool(), velocityEngine());
	}

}
