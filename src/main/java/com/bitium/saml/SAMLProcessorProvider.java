package com.bitium.saml;

import org.apache.commons.httpclient.HttpClient;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.Configuration;
import org.opensaml.xml.parse.ParserPool;
import org.springframework.security.saml.processor.HTTPArtifactBinding;
import org.springframework.security.saml.processor.HTTPPAOS11Binding;
import org.springframework.security.saml.processor.HTTPPostBinding;
import org.springframework.security.saml.processor.HTTPRedirectDeflateBinding;
import org.springframework.security.saml.processor.HTTPSOAP11Binding;
import org.springframework.security.saml.processor.SAMLBinding;
import org.springframework.security.saml.processor.SAMLProcessor;
import org.springframework.security.saml.processor.SAMLProcessorImpl;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.saml.websso.ArtifactResolutionProfile;
import org.springframework.security.saml.websso.ArtifactResolutionProfileImpl;

import java.util.ArrayList;
import java.util.Collection;

public class SAMLProcessorProvider {

    private static volatile SAMLProcessor processor;

    public static SAMLProcessor getProcessor() {
        SAMLProcessor local = processor;
        if (local == null) {
            synchronized (SAMLProcessor.class) {
                local = processor;
                if (local == null) {
                    processor = initProcessor();
                    local = processor;
                }
            }
        }
        return local;
    }

    private static SAMLProcessor initProcessor() {
        VelocityEngine velocityEngine = VelocityFactory.getEngine();
        Collection<SAMLBinding> bindings = new ArrayList<SAMLBinding>();
        bindings.add(httpRedirectDeflateBinding());
        bindings.add(httpPostBinding(velocityEngine));
        bindings.add(artifactBinding(Configuration.getParserPool(), velocityEngine));
        bindings.add(httpSOAP11Binding());
        bindings.add(httpPAOS11Binding());
        return new SAMLProcessorImpl(bindings);
    }

    private static ArtifactResolutionProfile artifactResolutionProfile() {
        final ArtifactResolutionProfileImpl artifactResolutionProfile =
                new ArtifactResolutionProfileImpl(httpClient());
        artifactResolutionProfile.setProcessor(new SAMLProcessorImpl(soapBinding()));
        return artifactResolutionProfile;
    }

    private static HttpClient httpClient() {
        return new HttpClient();
    }

    private static HTTPSOAP11Binding soapBinding() {
        return new HTTPSOAP11Binding(Configuration.getParserPool());
    }


    private static HTTPPostBinding httpPostBinding(VelocityEngine velocityEngine) {
        return new HTTPPostBinding(Configuration.getParserPool(), velocityEngine);
    }

    private static HTTPRedirectDeflateBinding httpRedirectDeflateBinding() {
        return new HTTPRedirectDeflateBinding(Configuration.getParserPool());
    }

    private static HTTPSOAP11Binding httpSOAP11Binding() {
        return new HTTPSOAP11Binding(Configuration.getParserPool());
    }

    private static HTTPPAOS11Binding httpPAOS11Binding() {
        return new HTTPPAOS11Binding(Configuration.getParserPool());
    }

    private static HTTPArtifactBinding artifactBinding(ParserPool parserPool, VelocityEngine velocityEngine) {
        return new HTTPArtifactBinding(parserPool, velocityEngine, artifactResolutionProfile());
    }

}
