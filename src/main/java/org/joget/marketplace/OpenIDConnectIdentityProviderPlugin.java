package org.joget.marketplace;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.*;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.joget.apps.app.service.AppPluginUtil;
import org.joget.apps.app.service.AppUtil;
import org.joget.commons.util.DynamicCacheElement;
import org.joget.commons.util.LogUtil;
import org.joget.directory.model.User;
import org.joget.directory.model.idp.AbstractMultiInstanceIdentityProviderPlugin;
import org.joget.directory.model.idp.IdpLogoutException;
import org.joget.workflow.util.WorkflowUtil;

import javax.cache.Cache;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLDecoder;

public class OpenIDConnectIdentityProviderPlugin extends AbstractMultiInstanceIdentityProviderPlugin {

    public static final String LOGGED_IN_TOKEN_SESSION_KEY = "LOGGED_IN_TOKEN";

    @Override
    public User handleCallback(HttpServletRequest callbackRequest) {
        //receive response from identity provider
        AuthenticationResponse authResp = null;
        try {
            authResp = AuthenticationResponseParser.parse(new URI(callbackRequest.getRequestURI() + "?" + callbackRequest.getQueryString()));
        } catch (ParseException e) {
            LogUtil.error(getClass().getName(), e, "Failed to process response.");
            return null;
        } catch (URISyntaxException e) {
            LogUtil.error(getClass().getName(), e, "Failed to parse URI.");
            return null;
        }

        if (authResp instanceof AuthenticationErrorResponse) {
            LogUtil.error(getClass().getName(), null, "Error in authentication response: " + authResp.toErrorResponse().getErrorObject().toString());
            return null;
        }

        State state = new State(callbackRequest.getParameter("state"));

        // read nonce from cache
        Cache cache = AppUtil.getCache("org.joget.cache.NONCE_CACHE");
        Nonce nonce = null;
        DynamicCacheElement cacheElement = (DynamicCacheElement) cache.get(state.toString());
        if (cacheElement != null) {
            nonce = (Nonce)cacheElement.getValue();
        }

        AuthenticationSuccessResponse successResponse = (AuthenticationSuccessResponse) authResp;
        AuthorizationCode authCode = null;
        if (successResponse != null) {
            if (!state.equals(successResponse.getState())) {
                LogUtil.error(getClass().getName(), null, "Unexpected authentication response.");
                return null;
            } else {
                authCode = successResponse.getAuthorizationCode();
            }
        }
        if (authCode != null) {
            String code;
            try {
                code = URLDecoder.decode(authCode.getValue(), "UTF-8");
            } catch (UnsupportedEncodingException e) {
                LogUtil.error(getClass().getName(), e, "Invalid code encoding.");
                return null;
            }

            Object[] accessTokenArray;
            try {
                accessTokenArray = getTokenForCode(code, nonce);
            } catch (GeneralException | BadJOSEException | JOSEException e) {
                LogUtil.error(getClass().getName(), e, "Error in obtaining access token.");
                return null;
            } catch (URISyntaxException e) {
                LogUtil.error(getClass().getName(), e, "Failed to parse URI.");
                return null;
            } catch (IOException e) {
                LogUtil.error(getClassName(), e, "Connection error, please try again.");
                return null;
            }
            OIDCTokens oidcTokens = (OIDCTokens) accessTokenArray[0];
            ClaimsSet idTokenClaims = (ClaimsSet) accessTokenArray[1];
            AccessToken accessToken = oidcTokens.getAccessToken();
            UserInfo userInfo;
            try {
                userInfo = getUserInfo(accessToken);
                userInfo.putAll(idTokenClaims);
            } catch (GeneralException e) {
                LogUtil.error(getClass().getName(), e, "Error in obtaining OpenID user info.");
                return null;
            } catch (URISyntaxException e) {
                LogUtil.error(getClass().getName(), e, "Failed to parse URI.");
                return null;
            } catch (IOException e) {
                LogUtil.error(getClassName(), e, "Connection error, please try again.");
                return null;
            }
            // put user ID JWT in the session to be used to log out of IdP later
            callbackRequest.getSession().setAttribute(LOGGED_IN_TOKEN_SESSION_KEY, oidcTokens.getIDToken());
            return getUser(userInfo);
        }
        return null;
    }

    @Override
    public String getAuthorizationEndpoint() {
        Nonce nonce = new Nonce();
        State state = new State();

        // save nonce in cache
        Cache cache = AppUtil.getCache("org.joget.cache.NONCE_CACHE");
        Long duration = 120L; // 2 minutes
        DynamicCacheElement element = new DynamicCacheElement(nonce, duration);
        cache.put(state.toString(), element);

        String responseTypes = getPropertyString("responseTypes");
        String scope = getPropertyString("scope");
        URI callbackUri;
        URI endpointUri;
        try {
            HttpServletRequest request = WorkflowUtil.getHttpServletRequest();
            callbackUri = new URI(getCallbackUrl(request));
            if (isIssuerAutoConfigure()) {
                OIDCProviderMetadata metadata = openIdIssuerDiscovery();
                endpointUri = metadata.getAuthorizationEndpointURI();
            } else {
                endpointUri = new URI(super.getAuthorizationEndpoint());
            }
        } catch (URISyntaxException e) {
            LogUtil.error(getClass().getName(), e, "Failed to parse URI");
            return "";
        } catch (GeneralException e) {
            LogUtil.error(getClassName(), e, "Unable to parse OpenID configuration from issuer.");
            return "";
        } catch (IOException e) {
            LogUtil.error(getClassName(), e, "Connection error.");
            return "";
        }

        AuthenticationRequest request = new AuthenticationRequest.Builder(
                new ResponseType(responseTypes),
                Scope.parse(scope),
                new ClientID(getPropertyString("clientId")),
                callbackUri
        )
                .endpointURI(endpointUri)
                .state(state)
                .nonce(nonce)
                .build();

        return request.toURI().toString();
    }

    @Override
    public void onLogout(HttpSession session) throws IdpLogoutException {
        try {
            URI logoutUri;
            if (isIssuerAutoConfigure()) {
                OIDCProviderMetadata metadata = openIdIssuerDiscovery();
                logoutUri = metadata.getEndSessionEndpointURI();
            } else if (!getPropertyString("logoutEndpoint").isEmpty()) {
                logoutUri = new URI(getPropertyString("logoutEndpoint"));
            } else {
                logoutUri = null;
            }

            if (logoutUri != null) {
                JWT idToken = (JWT) session.getAttribute(LOGGED_IN_TOKEN_SESSION_KEY);
                LogoutRequest logoutRequest = new LogoutRequest(logoutUri, idToken);
                HTTPResponse logoutResponse = logoutRequest.toHTTPRequest().send();
                if (!logoutResponse.indicatesSuccess()) {
                    throw new IdpLogoutException("Could not log out of IdP, status code: " + logoutResponse.getStatusCode());
                }
            }
        } catch (GeneralException e) {
            throw new IdpLogoutException("Error in obtaining OpenID user info.", e);
        } catch (IOException e) {
            throw new IdpLogoutException("Connection error, please try again.", e);
        } catch (URISyntaxException e) {
            throw new IdpLogoutException("Failed to parse URI", e);
        }
    }

    private OIDCProviderMetadata openIdIssuerDiscovery() throws GeneralException, IOException {
        Issuer issuer = new Issuer(getPropertyString("issuer"));
        return OIDCProviderMetadata.resolve(issuer);
    }

    private User getUser(UserInfo info) {
        // get id (sub + iss)
        // https://openid.net/specs/openid-connect-core-1_0.html#ClaimStability
        String id = info.getSubject().getValue() + "_" + info.getIssuer().getValue();
        id = id.replaceAll("[^0-9a-zA-Z.@_+\\-]", "-");

        // get user info
        String givenName = info.getGivenName();
        String familyName = info.getFamilyName();
        String email = info.getEmailAddress();
        String locale = info.getLocale();
        String timezone = info.getZoneinfo();

        User user = new User();
        user.setActive(1);
        user.setId(id);
        user.setUsername(id);
        user.setFirstName(givenName);
        user.setLastName(familyName);
        user.setEmail(email);
        user.setLocale(locale);
        user.setTimeZone(timezone);

        return user;
    }

    /**
     * Given an access token, calls the auth server to request user info
     *
     * @param accessTokenContent the access token obtained from the provider
     * @return OpenID UserInfo object
     * @throws URISyntaxException when error in URI parsing
     * @throws IOException        when error in HTTP request
     */
    private UserInfo getUserInfo(AccessToken accessTokenContent) throws URISyntaxException, IOException, GeneralException {
        URI userInfoEndpoint;
        if (isIssuerAutoConfigure()) {
            OIDCProviderMetadata providerMetadata = openIdIssuerDiscovery();
            userInfoEndpoint = providerMetadata.getUserInfoEndpointURI();
        } else {
            userInfoEndpoint = new URI(getPropertyString("userInfoEndpoint"));
        }
        HTTPResponse httpResponse = new UserInfoRequest(userInfoEndpoint, accessTokenContent).toHTTPRequest().send();

        // Parse the response
        UserInfoResponse userInfoResponse = UserInfoResponse.parse(httpResponse);

        if (!userInfoResponse.indicatesSuccess()) {
            String message = "The request failed, e.g. due to invalid or expired token";
            LogUtil.error(getClass().getName(), null, message);
            throw new GeneralException(message);
        }

        // Extract the claims
        return userInfoResponse.toSuccessResponse().getUserInfo();
    }

    /**
     * Given an authorization code, calls the auth server to request a token
     *
     * @param code  the authorization code
     * @param nonce the nonce of the request
     * @return an Object array of [{@link AccessToken}, {@link ClaimsSet}]
     * @throws URISyntaxException when error in URI parsing
     * @throws IOException        when error in HTTP request
     */
    private Object[] getTokenForCode(String code, Nonce nonce) throws URISyntaxException, IOException, GeneralException, BadJOSEException, JOSEException {
        AuthorizationCode authCode = new AuthorizationCode(code);
        URI tokenEndpoint;
        URI jwkSetUri;

        // Construct the code grant from the code obtained from the authz endpoint
        // and the original callback URI used at the authz endpoint
        HttpServletRequest httpServletRequest = WorkflowUtil.getHttpServletRequest();
        URI callback = new URI(getCallbackUrl(httpServletRequest));
        AuthorizationGrant codeGrant = new AuthorizationCodeGrant(authCode, callback);

        // The credentials to authenticate the client at the token endpoint
        ClientID clientID = new ClientID(getPropertyString("clientId"));
        Secret clientSecret = new Secret(getPropertyString("clientSecret"));
        ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);

        // The token endpoint
        if (isIssuerAutoConfigure()) {
            OIDCProviderMetadata providerMetadata = openIdIssuerDiscovery();
            tokenEndpoint = providerMetadata.getTokenEndpointURI();
            jwkSetUri = providerMetadata.getJWKSetURI();
        } else {
            tokenEndpoint = new URI(getPropertyString("tokenEndpoint"));
            jwkSetUri = new URI(getPropertyString("jsonWebKeySet"));
        }

        // Make the token request
        TokenRequest request = new TokenRequest(tokenEndpoint, clientAuth, codeGrant);
        TokenResponse tokenResponse = OIDCTokenResponseParser.parse(request.toHTTPRequest().send());
        if (!tokenResponse.indicatesSuccess()) {
            TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
            String message = "Error response:" + errorResponse.getErrorObject().toString() + " : " + errorResponse.getErrorObject().getDescription();
            LogUtil.error(getClass().getName(), null, message);
            throw new GeneralException(message);
        }

        OIDCTokenResponse successResponse = (OIDCTokenResponse) tokenResponse.toSuccessResponse();

        // Get the ID and access token, the server may also return a refresh token
        OIDCTokens oidcTokens = successResponse.getOIDCTokens();

        // The required parameters
        // Get the issuer URL from properties
        String issuerUrl = getPropertyString("issuer");

        // Check if the issuer URL contains "auth0" and adjust accordingly
        if (issuerUrl.contains("auth0")) {
            // Append a slash to the issuer URL if it contains "auth0"
            issuerUrl = issuerUrl.endsWith("/") ? issuerUrl : issuerUrl + "/";
        } else if (issuerUrl.endsWith("/")) {
            // else remove ending slash
            issuerUrl = issuerUrl.substring(0, issuerUrl.length() - 1);
        }

        // Create Issuer object
        Issuer iss = new Issuer(issuerUrl);

        //Issuer iss = new Issuer(dmImpl.getPropertyString("issuerUrl"));
        JWSAlgorithm jwsAlg = JWSAlgorithm.RS256;
        URL jwkSetURL = jwkSetUri.toURL();

        // Create validator for signed ID tokens
        IDTokenValidator validator = new IDTokenValidator(iss, clientID, jwsAlg, jwkSetURL);

        // Set the expected nonce, leave null if none
        ClaimsSet idTokenInfo = validator.validate(oidcTokens.getIDToken(), nonce);
        return new Object[]{oidcTokens, idTokenInfo};
    }

    private boolean isIssuerAutoConfigure() {
        return "auto".equals(getPropertyString("issuerConfig"));
    }


    @Override
    public String getName() {
        return AppPluginUtil.getMessage(getClassName() + ".pluginLabel", getClassName(), "message/openIDConnectIdentityProviderPlugin");
    }

    @Override
    public String getVersion() {
        return "9.0-SNAPSHOT";
    }

    @Override
    public String getDescription() {
        return AppPluginUtil.getMessage(getClassName() + ".pluginDesc", getClassName(), "message/openIDConnectIdentityProviderPlugin");
    }

    @Override
    public String getPropertyOptions() {
        return AppUtil.readPluginResource(
                getClassName(),
                "/properties/openIDConnectIdentityProviderPlugin.json",
                null,
                true,
                "message/openIDConnectIdentityProviderPlugin");
    }
}
