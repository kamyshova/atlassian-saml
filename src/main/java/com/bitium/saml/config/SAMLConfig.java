package com.bitium.saml.config;

import com.atlassian.sal.api.pluginsettings.PluginSettings;
import com.atlassian.sal.api.pluginsettings.PluginSettingsFactory;
import org.apache.commons.lang.StringUtils;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

public class SAMLConfig {
    private static final Logger logger = LoggerFactory.getLogger(SAMLConfig.class);

    private PluginSettings pluginSettings;
    private MetadataProvider metadataProvider;

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
    public static final String KEY_STORE_PASSWORD_SETTING = "saml2.keystorePassword";
    public static final String SIGN_KEY_SETTING = "saml2.signKey";
    public static final String REQUEST_BINDING_SETTING = "saml2.requestBinding";
    public static final String METADATA_FILE_PATH_SETTING = "saml2.metadata";
    public static final String KEYSTORE_FILE_PATH_SETTING = "saml2.keystore";
    public static final String BASE_URL_SETTING = "saml2.baseUrl";

    static {
        try {
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException e) {
            logger.error("Error during DefaultBootstrap.bootstrap()", e);
        }
    }

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

    public void setKeyStorePasswordSetting(final String keyStorePassword) {
        pluginSettings.put(KEY_STORE_PASSWORD_SETTING, keyStorePassword);
    }

    public void setSignKeySetting(final String signKeySetting) {
        pluginSettings.put(SIGN_KEY_SETTING, signKeySetting);
    }

    public void setRequestBindingSetting(final String requestBindingSetting) {
        pluginSettings.put(REQUEST_BINDING_SETTING, requestBindingSetting);
    }

    public void setMetadataFile(final String metadataFilePath) {
        pluginSettings.put(METADATA_FILE_PATH_SETTING, metadataFilePath);
    }

    public void setKeystoreFile(final String keystoreFilePath) {
        pluginSettings.put(KEYSTORE_FILE_PATH_SETTING, keystoreFilePath);
    }

    public void setBaseUrl(final String baseURL) {
        pluginSettings.put(BASE_URL_SETTING, baseURL);
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

    public String getAlias() {
        return "confluenceSAML";
    }

    public String getBaseUrl() {
        return StringUtils.defaultString((String)pluginSettings.get(BASE_URL_SETTING));
    }

    public String getSpEntityId() {
        return StringUtils.defaultString((String)pluginSettings.get(SP_ENTITY_ID_SETTING));
    }

    public String getKeyStorePasswordSetting() {
        return StringUtils.defaultString((String)pluginSettings.get(KEY_STORE_PASSWORD_SETTING));
    }

    public String getSignKeySetting() {
        return StringUtils.defaultString((String)pluginSettings.get(SIGN_KEY_SETTING));
    }

    public String getRequestBindingSetting() {
        return StringUtils.defaultString((String)pluginSettings.get(REQUEST_BINDING_SETTING));
    }

    public String getMetadata() {
        return StringUtils.defaultString((String)pluginSettings.get(METADATA_FILE_PATH_SETTING));
    }

    public String getKeystore() {
        return StringUtils.defaultString((String)pluginSettings.get(KEYSTORE_FILE_PATH_SETTING));
    }
}
