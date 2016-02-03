package com.bitium.saml.servlet;

import com.bitium.saml.SAMLContext;
import com.bitium.saml.config.SAMLConfig;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.websso.SingleLogoutProfileImpl;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class SsoLogoutServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;

    private Log log = LogFactory.getLog(SsoLogoutServlet.class);

    private SAMLConfig saml2Config;

    @Override
    public void init() throws ServletException {
        super.init();
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        try {
            SAMLContext context = new SAMLContext(request, saml2Config);
            SAMLMessageContext messageContext = context.createSamlMessageContext(request, response);

            SAMLCredential credential = (SAMLCredential)request.getSession().getAttribute("SAMLCredential");

            // Send request
            SingleLogoutProfileImpl profile = new SingleLogoutProfileImpl();
            profile.setMetadata(context.getMetadataManager());
            profile.setProcessor(context.getSamlProcessor());
            profile.sendLogoutRequest(messageContext, credential);
        } catch (Exception e) {
            log.error("saml plugin error + " + e.getMessage());
            response.sendRedirect(saml2Config.getBaseUrl() + "/login.action?samlerror=general");
        }
    }

    public void setSaml2Config(SAMLConfig saml2Config) {
        this.saml2Config = saml2Config;
    }
}
