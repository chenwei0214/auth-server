package org.example.auth.extension.grant.password;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.util.Assert;

import java.util.Map;
import java.util.Set;

/**
 * @author: wei.chen
 * @project: auth-server
 * @package: org.example.auth.extension.grant.password
 * @class: OAuth2UsernamePasswordAuthenticationToken
 * @description: 密码模式登录token
 * @created: created in 2023/4/1 14:40
 * @modified by: wei.chen
 */
public class OAuth2UsernamePasswordAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

    private final String username;
    private final String password;
    private final Set<String> scopes;

    /**
     * Sub-class constructor.
     * @param username the authenticated username
     * @param password the authenticated password
     * @param scopes the authenticated scope
     * @param clientPrincipal        the authenticated client principal
     * @param additionalParameters   the additional parameters
     */
    protected OAuth2UsernamePasswordAuthenticationToken(String username, String password , @Nullable Set<String> scopes,
                                                        Authentication clientPrincipal, Map<String, Object> additionalParameters) {
        super(AuthorizationGrantType.PASSWORD, clientPrincipal, additionalParameters);
        Assert.hasText(username, "username cannot be empty");
        Assert.hasText(password, "password cannot be empty");
        Assert.notEmpty(scopes,"scopes cannot be empty");
        this.username = username;
        this.password = password;
        this.scopes = scopes;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public Set<String> getScopes() {
        return scopes;
    }
}
