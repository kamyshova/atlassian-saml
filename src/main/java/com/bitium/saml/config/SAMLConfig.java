package com.bitium.saml.config;

import java.io.File;
import java.util.List;
import org.apache.commons.lang.StringUtils;

import com.atlassian.sal.api.pluginsettings.PluginSettings;
import com.atlassian.sal.api.pluginsettings.PluginSettingsFactory;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObject;

public class SAMLConfig {

    private PluginSettings pluginSettings;
    private MetadataProvider metadataProvider;

    private String defaultBaseURL;

    public static final String ENTITY_ID_SETTING = "saml2.entityId";
    public static final String LOGIN_URL_SETTING = "saml2.loginUrl";
    public static final String LOGOUT_URL_SETTING = "saml2.logoutUrl";
    public static final String UID_ATTRIBUTE_SETTING = "salm2.uidAttribute";
    public static final String X509_CERTIFICATE_SETTING = "saml2.x509Certificate";
    public static final String IDP_REQUIRED_SETTING = "saml2.idpRequired";
    public static final String REDIRECT_URL_SETTING = "saml2.redirectUrl";
    public static final String AUTO_CREATE_USER_SETTING = "saml2.autoCreateUser";
    public static final String AUTO_CREATE_USER_DEFAULT_GROUP_SETTING = "saml2.autoCreateUserDefaultGroup";
    public static final String MAX_AUTHENTICATION_AGE = "saml2.maxAuthenticationAge";
    public static final String SP_ENTITY_ID_SETTING = "saml2.spEntityId";

    public void setPluginSettingsFactory(PluginSettingsFactory pluginSettingsFactory) {
        this.pluginSettings = pluginSettingsFactory.createGlobalSettings();
    }

    public void setMetadataProvider(final MetadataProvider metadataProvider) {
        this.metadataProvider = metadataProvider;
    }

    public MetadataProvider getMetadataProvider() {
        return metadataProvider;
    }

    @Deprecated
    public void setLoginUrl(String loginUrl) {
        pluginSettings.put(LOGIN_URL_SETTING, loginUrl);
    }

    @Deprecated
    public void setLogoutUrl(String logoutUrl) {
        pluginSettings.put(LOGOUT_URL_SETTING, logoutUrl);
    }

    @Deprecated
    public void setEntityId(String entityId) {
        pluginSettings.put(ENTITY_ID_SETTING, entityId);
    }

    public void setUidAttribute(String uidAttribute) {
        pluginSettings.put(UID_ATTRIBUTE_SETTING, uidAttribute);
    }

    @Deprecated
    public void setX509Certificate(String x509Certificate) {
        pluginSettings.put(X509_CERTIFICATE_SETTING, x509Certificate);
    }

    public void setIdpRequired(String idpRequired) {
        pluginSettings.put(IDP_REQUIRED_SETTING, idpRequired);
    }

    public void setRedirectUrl(String redirectUrl) {
        pluginSettings.put(REDIRECT_URL_SETTING, redirectUrl);
    }

    public void setAutoCreateUser(String autoCreateUser) {
        pluginSettings.put(AUTO_CREATE_USER_SETTING, autoCreateUser);
    }

    public void setAutoCreateUserDefaultGroup(String autoCreateUserDefaultGroup) {
        pluginSettings.put(AUTO_CREATE_USER_DEFAULT_GROUP_SETTING, autoCreateUserDefaultGroup);
    }
	
	public void setMaxAuthenticationAge(long maxAuthenticationAge) {
		pluginSettings.put(MAX_AUTHENTICATION_AGE, String.valueOf(maxAuthenticationAge));
	}

    public void setSpEntityId(final String spEntityId) {
        pluginSettings.put(SP_ENTITY_ID_SETTING, spEntityId);
    }

    public void setMetadataFile(final File metadataFile) {
        if (metadataFile == null) {
            throw new IllegalArgumentException("Metadata file should not be null");
        }
        try {
            final FilesystemMetadataProvider metadataProvider = new FilesystemMetadataProvider(metadataFile);
            metadataProvider.setParserPool(Configuration.getParserPool());
            metadataProvider.initialize();
            this.metadataProvider = metadataProvider;
        } catch (MetadataProviderException e) {
            throw new RuntimeException("Metadata provider wasn't created for the given metadata file", e);
        }
    }
	
	public long getMaxAuthenticationAge() {
		String value=StringUtils.defaultString((String)pluginSettings.get(MAX_AUTHENTICATION_AGE));
		return value==""?Long.MIN_VALUE:Long.parseLong(value);
	}
	
    public String getIdpRequired() {
        return StringUtils.defaultString((String)pluginSettings.get(IDP_REQUIRED_SETTING));
    }

    public boolean getIdpRequiredFlag() {
        if (StringUtils.defaultString((String)pluginSettings.get(IDP_REQUIRED_SETTING)).equals("true")) {
            return true;
        } else {
            return false;
        }
    }

    public String getAutoCreateUser() {
        return StringUtils.defaultString((String)pluginSettings.get(AUTO_CREATE_USER_SETTING));
    }

    public boolean getAutoCreateUserFlag() {
        if (StringUtils.defaultString((String)pluginSettings.get(AUTO_CREATE_USER_SETTING)).equals("true")) {
            return true;
        } else {
            return false;
        }
    }

    public String getAutoCreateUserDefaultGroup() {
        return StringUtils.defaultString((String)pluginSettings.get(AUTO_CREATE_USER_DEFAULT_GROUP_SETTING));
    }

    @Deprecated
    public String getLoginUrl() {
        return StringUtils.defaultString((String)pluginSettings.get(LOGIN_URL_SETTING));
    }

    public String getLogoutUrl() {
        if (metadataProvider != null) {
            try {
                final String entityId = retrieveEntityId(metadataProvider);
                final EntityDescriptor entityDescriptor = metadataProvider.getEntityDescriptor(entityId);
                final List<RoleDescriptor> roleDescriptors = entityDescriptor.getRoleDescriptors();
                final String logoutUrl = retrieveLogoutUrl(roleDescriptors);
                if (logoutUrl != null) {
                    return logoutUrl;
                } else {
                    throw new RuntimeException("Logout url wasn't found in metadata file");
                }
            } catch (MetadataProviderException e) {
                throw new RuntimeException("Logout url could not be retrieved from metadata provider", e);
            }
        } else {
            throw new RuntimeException("Logout url could not be retrieved because metadata provider is not set");
        }
    }

    private String retrieveLogoutUrl(final List<RoleDescriptor> roleDescriptors) {
        for (RoleDescriptor roleDescriptor: roleDescriptors) {
            final List<Endpoint> endpoints = roleDescriptor
                    .getEndpoints(SingleLogoutService.DEFAULT_ELEMENT_NAME);

            for (Endpoint endpoint: endpoints) {
                if (endpoint.getBinding().equals(SAMLConstants.SAML2_REDIRECT_BINDING_URI)) {
                    return endpoint.getLocation();
                }
            }
        }
        return null;
    }

    private String retrieveEntityId(final MetadataProvider metadataProvider) throws MetadataProviderException {
        final XMLObject metadata = metadataProvider.getMetadata();
        if (metadata instanceof EntityDescriptor) {
            final EntityDescriptor entity = (EntityDescriptor) metadata;
            return entity.getEntityID();
        } else {
            throw new RuntimeException("Multiple entity descriptors is not supported yet.");
        }
    }

    @Deprecated
    public String getIdpEntityId() {
        return StringUtils.defaultString((String)pluginSettings.get(ENTITY_ID_SETTING));
    }

    public String getUidAttribute() {
        return StringUtils.defaultString((String)pluginSettings.get(UID_ATTRIBUTE_SETTING), "NameID");
    }

    @Deprecated
    public String getX509Certificate() {
        return StringUtils.defaultString((String)pluginSettings.get(X509_CERTIFICATE_SETTING));
    }

    public String getRedirectUrl() {
        return StringUtils.defaultString((String)pluginSettings.get(REDIRECT_URL_SETTING));
    }

    public void setDefaultBaseUrl(String defaultBaseURL) {
        this.defaultBaseURL = defaultBaseURL;
    }

    public String getAlias() {
        return "confluenceSAML";
    }

    public String getBaseUrl() {
        return StringUtils.defaultString(defaultBaseURL);
    }

    public String getSpEntityId() {
        return StringUtils.defaultString((String)pluginSettings.get(SP_ENTITY_ID_SETTING));
    }

}
