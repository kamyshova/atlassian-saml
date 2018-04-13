package com.bitium.saml.filter;

import com.atlassian.sal.api.auth.LoginUriProvider;
import com.bitium.saml.config.SAMLConfig;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

public class LoginFilter implements Filter {

    private SAMLConfig config;
    private LoginUriProvider loginUriProvider;

    public void init(FilterConfig filterConfig) throws ServletException {
    }

    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {
        boolean idpRequired = config.getIdpRequiredFlag();
        HttpServletRequest req = (HttpServletRequest)request;
        HttpServletResponse res = (HttpServletResponse)response;

        if (idpRequired) {
            try {
                res.sendRedirect(loginUriProvider.getLoginUri((new URI(req.getRequestURI()))).toString() + "&samlerror=general");
            } catch (URISyntaxException e) {
            }
        } else {
            chain.doFilter(request, response);
        }
    }

    public void destroy() {
    }

    public void setConfig(SAMLConfig config) {
        this.config = config;
    }

    public void setLoginUriProvider(LoginUriProvider loginUriProvider) {
        this.loginUriProvider = loginUriProvider;
    }

}
