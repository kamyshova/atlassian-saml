package com.bitium.saml;

import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.security.saml.SAMLConstants;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.processor.SAMLProcessor;
import org.springframework.security.saml.websso.SingleLogoutProfile;
import org.springframework.security.saml.websso.SingleLogoutProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfile;
import org.springframework.security.saml.websso.WebSSOProfileConsumer;
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl;
import org.springframework.security.saml.websso.WebSSOProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfileOptions;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SAMLContext {

	private MetadataManager metadataManager;
	private SAMLContextProvider contextProvider;
	private String requestBinding;
	private long maxAuthenticationAge;

    public SAMLContext(MetadataManager metadataManager, SAMLContextProvider contextProvider,
                       String requestBinding, long maxAuthenticationAge) {
        this.metadataManager = metadataManager;
        this.contextProvider = contextProvider;
        this.requestBinding = requestBinding;
        this.maxAuthenticationAge = maxAuthenticationAge;
    }

    public SAMLMessageContext getLocalEntity(HttpServletRequest request, HttpServletResponse response)
            throws MetadataProviderException {
        SAMLMessageContext messageContext = contextProvider.getLocalEntity(request, response);
        postProcessMessage(request, messageContext);
        return messageContext;
    }

    public SAMLMessageContext getLocalAndPeerEntity(HttpServletRequest request, HttpServletResponse response)
            throws MetadataProviderException {
        SAMLMessageContext messageContext = contextProvider.getLocalAndPeerEntity(request, response);
        postProcessMessage(request, messageContext);
        return messageContext;
    }

    public WebSSOProfileConsumer getWebSSOProfileConsumer(SAMLProcessor samlProcessor) {
        WebSSOProfileConsumerImpl webSSOProfileConsumer =
                new WebSSOProfileConsumerImpl(samlProcessor, metadataManager);
        webSSOProfileConsumer.setMaxAuthenticationAge(maxAuthenticationAge);
        return webSSOProfileConsumer;
    }

    public WebSSOProfileOptions getSSOProfileOptions() {
        WebSSOProfileOptions options = new WebSSOProfileOptions();
        options.setBinding(requestBinding);
        options.setIncludeScoping(false);
        return options;
    }

    public WebSSOProfile getWebSSOProfile(SAMLProcessor samlProcessor) {
        return new WebSSOProfileImpl(samlProcessor, metadataManager);
    }

    public SAMLContextProvider getSamlContextProvider() {
	    return this.contextProvider;
    }

    public SingleLogoutProfile getLogoutProfile(SAMLProcessor samlProcessor) {
        SingleLogoutProfileImpl profile = new SingleLogoutProfileImpl();
        profile.setMetadata(metadataManager);
        profile.setProcessor(samlProcessor);
        return profile;
    }

    private void postProcessMessage(HttpServletRequest request, SAMLMessageContext messageContext) {
        SPSSODescriptor spDescriptor = (SPSSODescriptor) messageContext.getLocalEntityRoleMetadata();

        String responseURL = request.getRequestURL().toString();
        spDescriptor.getDefaultAssertionConsumerService().setResponseLocation(responseURL);
        for (AssertionConsumerService service : spDescriptor.getAssertionConsumerServices()) {
            service.setResponseLocation(responseURL);
        }

        spDescriptor.setAuthnRequestsSigned(true);
        messageContext.setCommunicationProfileId(SAMLConstants.SAML2_WEBSSO_PROFILE_URI);
    }
}
