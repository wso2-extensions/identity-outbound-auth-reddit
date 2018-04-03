/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.authenticator.reddit;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.apache.oltu.oauth2.common.utils.JSONUtils;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Authenticator of Reddit
 * @since 1.0.1
 */
public class RedditAuthenticator extends OpenIDConnectAuthenticator implements FederatedApplicationAuthenticator {

    private static Log log = LogFactory.getLog(RedditAuthenticator.class);

    /**
     * Get Reddit authorization endpoint.
     */
    @Override
    protected String getAuthorizationServerEndpoint(Map<String, String> authenticatorProperties) {
        return RedditAuthenticatorConstants.REDDIT_OAUTH_ENDPOINT;
    }

    /**
     * Get Reddit token endpoint.
     */
    @Override
    protected String getTokenEndpoint(Map<String, String> authenticatorProperties) {
        return RedditAuthenticatorConstants.REDDIT_TOKEN_ENDPOINT;
    }

    /**
     * Get Reddit user info endpoint.
     */
    @Override
    protected String getUserInfoEndpoint(OAuthClientResponse token, Map<String, String> authenticatorProperties) {
        return RedditAuthenticatorConstants.REDDIT_USERINFO_ENDPOINT;
    }

    /**
     * Check ID token in Reddit OAuth.
     */
    @Override
    protected boolean requiredIDToken(Map<String, String> authenticatorProperties) {
        return false;
    }

    /**
     * Get the friendly name of the Authenticator
     */
    @Override
    public String getFriendlyName() {
        return RedditAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Get the name of the Authenticator
     */
    @Override
    public String getName() {
        return RedditAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    /**
     * Get the scope
     */
    public String getScope(String scope, Map<String, String> authenticatorProperties) {
        scope = authenticatorProperties.get(RedditAuthenticatorConstants.SCOPE);
        if (StringUtils.isEmpty(scope)) {
            scope = RedditAuthenticatorConstants.USER_SCOPE;
        }
        return scope;
    }

    /**
     * check and process the httpServletRequest to process.
     *
     * @param httpServletRequest http request
     * @return weather true or false
     */
    public boolean canHandle(HttpServletRequest httpServletRequest) {
        return httpServletRequest.getParameter(RedditAuthenticatorConstants.CODE) != null || httpServletRequest
                .getParameter(RedditAuthenticatorConstants.OAUTH2_PARAM_ERROR) != null;
    }

    /**
     * Handle error response when unauthorized the registered app.
     *
     * @param request httpServletRequest
     * @throws InvalidCredentialsException
     */
    private void handleErrorResponse(HttpServletRequest request) throws InvalidCredentialsException {
        if (request.getParameter(RedditAuthenticatorConstants.OAUTH2_PARAM_ERROR) != null) {
            StringBuilder errorMessage = new StringBuilder();
            String error = request.getParameter(RedditAuthenticatorConstants.OAUTH2_PARAM_ERROR);
            String state = request.getParameter(OIDCAuthenticatorConstants.OAUTH2_PARAM_STATE);
            errorMessage.append(RedditAuthenticatorConstants.ERROR).append(error)
                    .append(RedditAuthenticatorConstants.STATE).append(state);
            if (log.isDebugEnabled()) {
                log.debug("Failed to authenticate via Reddit when unauthorized the registered app : " + errorMessage
                        .toString());
            }
            throw new InvalidCredentialsException(errorMessage.toString());
        }
    }

    /**
     * Process the response of first call
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {
        try {
            handleErrorResponse(request);
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            String clientId = authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_ID);
            String clientSecret = authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_SECRET);
            String tokenEndPoint = getTokenEndpoint(authenticatorProperties);
            String callbackUrl = getCallbackUrl(authenticatorProperties);
            OAuthAuthzResponse authorizationResponse = OAuthAuthzResponse.oauthCodeAuthzResponse(request);
            String code = authorizationResponse.getCode();
            OAuthClientRequest accessRequest =
                    getAccessRequest(tokenEndPoint, clientId, code, clientSecret, callbackUrl);
            RedditOauthClient oAuthClient = new RedditOauthClient(new URLConnectionClient(), clientId, clientSecret);
            OAuthClientResponse oAuthResponse = getOauthResponse(oAuthClient, accessRequest);
            String accessToken = oAuthResponse.getParam(OIDCAuthenticatorConstants.ACCESS_TOKEN);

            if (StringUtils.isBlank(accessToken)) {
                throw new AuthenticationFailedException("Access token is empty or null");
            }
            context.setProperty(OIDCAuthenticatorConstants.ACCESS_TOKEN, accessToken);
            String json = sendRequest(RedditAuthenticatorConstants.REDDIT_USERINFO_ENDPOINT, accessToken);
            AuthenticatedUser authenticatedUserObj;
            Map<ClaimMapping, String> claims;
            authenticatedUserObj = AuthenticatedUser
                    .createFederateAuthenticatedUserFromSubjectIdentifier(JSONUtils.parseJSON(json)
                            .get(RedditAuthenticatorConstants.USER_ID).toString());
            authenticatedUserObj.setAuthenticatedSubjectIdentifier(JSONUtils.parseJSON(json)
                    .get(RedditAuthenticatorConstants.USER_ID).toString());
            claims = getSubjectAttributes(oAuthResponse, authenticatorProperties);
            authenticatedUserObj.setUserAttributes(claims);
            context.setSubject(authenticatedUserObj);
        } catch (OAuthProblemException | IOException e) {
            throw new AuthenticationFailedException("Authentication process failed", e);
        }
    }

    /**
     * Build the request for get accessToken
     *
     * @param tokenEndPoint endpoint for get accessToken
     * @param clientId      clientId
     * @param code          authorization code
     * @param clientSecret  clientSecret
     * @param callbackurl   redirect Url
     * @throws AuthenticationFailedException
     */
    private OAuthClientRequest getAccessRequest(String tokenEndPoint, String clientId, String code, String clientSecret,
                                                String callbackurl) throws AuthenticationFailedException {
        OAuthClientRequest accessRequest;
        try {
            accessRequest = OAuthClientRequest.tokenLocation(tokenEndPoint)
                    .setGrantType(GrantType.AUTHORIZATION_CODE)
                    .setClientId(clientId)
                    .setClientSecret(clientSecret)
                    .setRedirectURI(callbackurl)
                    .setCode(code)
                    .buildBodyMessage();
        } catch (OAuthSystemException e) {
            throw new AuthenticationFailedException("Error while build the accessRequest", e);
        }
        return accessRequest;
    }

    /**
     * Get OauthResponse for accessToken request
     *
     * @param oAuthClient   oAuthClient
     * @param accessRequest accessRequest
     * @throws AuthenticationFailedException
     */
    private OAuthClientResponse getOauthResponse(OAuthClient oAuthClient, OAuthClientRequest accessRequest)
            throws AuthenticationFailedException {
        OAuthClientResponse oAuthResponse;
        try {
            oAuthResponse = oAuthClient.accessToken(accessRequest);
        } catch (OAuthSystemException | OAuthProblemException e) {
            throw new AuthenticationFailedException("Exception while requesting access token", e);
        }
        return oAuthResponse;
    }

    /**
     * Request user claims from user info endpoint.
     *
     * @param url         User info endpoint.
     * @param accessToken Access token.
     * @return Response string.
     * @throws IOException
     */
    @Override
    protected String sendRequest(String url, String accessToken)
            throws IOException {

        if (log.isDebugEnabled()) {
            log.debug("Claim URL: " + url);
        }
        if (url == null) {
            return StringUtils.EMPTY;
        }
        URL obj = new URL(url);
        HttpURLConnection urlConnection = (HttpURLConnection) obj.openConnection();
        urlConnection.setRequestMethod(RedditAuthenticatorConstants.HTTP_GET);
        urlConnection.setRequestProperty(RedditAuthenticatorConstants.AUTHORIZATION,
                RedditAuthenticatorConstants.AUTHORIZATION_BEARER + accessToken);
        urlConnection.setRequestProperty(RedditAuthenticatorConstants.CONTENT_TYPE,
                RedditAuthenticatorConstants.CONTENT_TYPE_JSON);
        urlConnection.setRequestProperty(RedditAuthenticatorConstants.REQUEST_HOST_HEADER,
                RedditAuthenticatorConstants.REDDIT_HOST);
        urlConnection.setRequestProperty(RedditAuthenticatorConstants.REDDIT_USER_AGENT,
                RedditAuthenticatorConstants.USER_AGENT);
        BufferedReader reader = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));
        StringBuilder builder = new StringBuilder();
        String inputLine = reader.readLine();
        while (inputLine != null) {
            builder.append(inputLine).append("\n");
            inputLine = reader.readLine();
        }
        reader.close();
        if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_ID_TOKEN)) {
            log.debug("response: " + builder.toString());
        }
        return builder.toString();
    }

    /**
     * Get Configuration Properties
     */
    @Override
    public List<Property> getConfigurationProperties() {
        List<Property> configProperties = new ArrayList<>();

        Property clientId = new Property();
        clientId.setName(OIDCAuthenticatorConstants.CLIENT_ID);
        clientId.setDisplayName(RedditAuthenticatorConstants.REDDIT_CLIENT_ID);
        clientId.setRequired(true);
        clientId.setDescription("Enter Reddit  client identifier value");
        clientId.setDisplayOrder(1);
        configProperties.add(clientId);

        Property clientSecret = new Property();
        clientSecret.setName(OIDCAuthenticatorConstants.CLIENT_SECRET);
        clientSecret.setDisplayName(RedditAuthenticatorConstants.REDDIT_CLIENT_SECRET);
        clientSecret.setRequired(true);
        clientSecret.setConfidential(true);
        clientSecret.setDescription("Enter Reddit client secret value");
        clientSecret.setDisplayOrder(2);
        configProperties.add(clientSecret);

        Property callbackUrl = new Property();
        callbackUrl.setDisplayName(RedditAuthenticatorConstants.REDDIT_CALLBACK_URL);
        callbackUrl.setName(IdentityApplicationConstants.OAuth2.CALLBACK_URL);
        callbackUrl.setDescription("Enter value corresponding to callback url.");
        callbackUrl.setDisplayOrder(3);
        configProperties.add(callbackUrl);
        return configProperties;
    }
}