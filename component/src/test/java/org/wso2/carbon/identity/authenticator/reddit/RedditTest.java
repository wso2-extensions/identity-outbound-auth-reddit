/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */
package org.wso2.carbon.identity.authenticator.reddit;

import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.client.response.OAuthJSONAccessTokenResponse;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.reflect.Whitebox;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;

@RunWith(PowerMockRunner.class)
@PrepareForTest({OAuthAuthzResponse.class, AuthenticatedUser.class, OAuthClientRequest.class, URL.class})
public class RedditTest {

    @Mock
    OAuthClientResponse oAuthClientResponse;
    @Mock
    HttpServletRequest httpServletRequest;
    @Mock
    OAuthAuthzResponse mockOAuthAuthzResponse;
    @Mock
    private AuthenticatedUser authenticatedUser;
    @Spy
    private AuthenticationContext context = new AuthenticationContext();
    @Mock
    private HttpServletResponse httpServletResponse;

    @Mock
    private OAuthClient mockOAuthClient;

    @Mock
    private OAuthClientRequest mockOAuthClientRequest;
    @Mock
    private OAuthJSONAccessTokenResponse oAuthJSONAccessTokenResponse;

    @DataProvider(name = "authenticatorProperties")
    public Object[][] getAuthenticatorPropertiesData() {

        Map<String, String> authenticatorProperties = new HashMap<>();
        authenticatorProperties.put(OIDCAuthenticatorConstants.CLIENT_ID, "test-client-id");
        authenticatorProperties.put(OIDCAuthenticatorConstants.CLIENT_SECRET, "test-client-secret");
        authenticatorProperties.put("callbackUrl", "http://localhost:9443/commonauth");
        authenticatorProperties.put("scope", "");
        return new Object[][]{{authenticatorProperties}};
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {

        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

    RedditAuthenticator redditAuthenticator;

    @BeforeMethod
    public void setUp() {

        redditAuthenticator = new RedditAuthenticator();
        initMocks(this);
    }

    @Test(description = "Test case for getTokenEndpoint method", dataProvider = "authenticatorProperties")
    public void testGetTokenEndpoint(Map<String, String> authenticatorProperties) {

        String tokenEndpoint = redditAuthenticator.getTokenEndpoint(authenticatorProperties);
        Assert.assertEquals(RedditAuthenticatorConstants.REDDIT_TOKEN_ENDPOINT, tokenEndpoint);
    }

    @Test(description = "Test case for getUserInfoEndpoint method", dataProvider = "authenticatorProperties")
    public void testGetUserInfoEndpoint(Map<String, String> authenticatorProperties) {

        String tokenEndpoint = redditAuthenticator.getUserInfoEndpoint(oAuthClientResponse, authenticatorProperties);
        Assert.assertEquals(RedditAuthenticatorConstants.REDDIT_USERINFO_ENDPOINT, tokenEndpoint);
    }

    @Test(description = "Test case for requiredIDToken method", dataProvider = "authenticatorProperties")
    public void testRequiredIDToken(Map<String, String> authenticatorProperties) {

        Assert.assertFalse(redditAuthenticator.requiredIDToken(authenticatorProperties));
    }

    @Test(description = "Test case for getFriendlyName method")
    public void testGetFriendlyName() {

        Assert.assertEquals(RedditAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME,
                redditAuthenticator.getFriendlyName());
    }

    @Test(description = "Test case for getAuthorizationServerEndpoint method", dataProvider = "authenticatorProperties")
    public void testGetAuthorizationServerEndpoint(Map<String, String> authenticatorProperties) {

        Assert.assertEquals(RedditAuthenticatorConstants.REDDIT_OAUTH_ENDPOINT,
                redditAuthenticator.getAuthorizationServerEndpoint(authenticatorProperties));
    }

    @Test(description = "Test case for getName method")
    public void testGetName() {

        Assert.assertEquals(RedditAuthenticatorConstants.AUTHENTICATOR_NAME, redditAuthenticator.getName());
    }

    @Test(description = "Test case for getScope method", dataProvider = "authenticatorProperties")
    public void testGetScope(Map<String, String> authenticatorProperties) {

        Assert.assertEquals(RedditAuthenticatorConstants.USER_SCOPE,
                redditAuthenticator.getScope("scope", authenticatorProperties));
    }

    @Test(description = "Test case for canHandle method")
    public void testCanHandle() {

        Assert.assertNotNull(redditAuthenticator.canHandle(httpServletRequest));
    }

    @Test
    public void testGetConfigurationProperties() {

        Assert.assertEquals(3, redditAuthenticator.getConfigurationProperties().size());
    }

    @Test(expectedExceptions = UnknownHostException.class)
    public void testsendRequest() throws Exception {

        Assert.assertNotNull(redditAuthenticator.sendRequest("http://test-url", "dummy-token"));
    }

    @Test(expectedExceptions = AuthenticationFailedException.class, description = "Test case for processAuthenticationResponse", dataProvider = "authenticatorProperties")
    public void testProcessAuthenticationResponse(Map<String, String> authenticatorProperties) throws Exception {

        RedditAuthenticator spyAuthenticator = PowerMockito.spy(new RedditAuthenticator());
        PowerMockito.mockStatic(OAuthAuthzResponse.class);
        when(OAuthAuthzResponse.oauthCodeAuthzResponse(Mockito.any(HttpServletRequest.class)))
                .thenReturn(mockOAuthAuthzResponse);
        when(oAuthClientResponse.getParam(OIDCAuthenticatorConstants.ACCESS_TOKEN)).thenReturn("test-token");
        PowerMockito.doReturn("{\"token\":\"test-token\",\"id\":\"testuser\"}").when(spyAuthenticator, "sendRequest",
                Mockito.anyString(), Mockito.anyString());
        PowerMockito.mockStatic(AuthenticatedUser.class);
        when(AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(Mockito.anyString()))
                .thenReturn(authenticatedUser);
        context.setAuthenticatorProperties(authenticatorProperties);
        spyAuthenticator.processAuthenticationResponse(httpServletRequest, httpServletResponse, context);
        Assert.assertNotNull(context.getSubject());
    }

    @Test(expectedExceptions = InvalidCredentialsException.class, description = "Negative test case for HandleErrorResponse")
    public void testHandleErrorResponse() throws Exception {

        when(httpServletRequest.getParameter(RedditAuthenticatorConstants.OAUTH2_PARAM_ERROR)).thenReturn("parameter");
        Whitebox.invokeMethod(redditAuthenticator, "handleErrorResponse", httpServletRequest);
    }

    @Test(description = "Test case for getOauthResponse method")
    public void testGetOauthResponse() throws Exception {

        OAuthClientResponse oAuthClientResponse = GetOauthResponse(mockOAuthClient, mockOAuthClientRequest);
        Assert.assertNotNull(oAuthClientResponse);
    }

    public OAuthClientResponse GetOauthResponse(OAuthClient mockOAuthClient, OAuthClientRequest mockOAuthClientRequest) throws Exception {

        Mockito.when(mockOAuthClient.accessToken(mockOAuthClientRequest)).thenReturn(oAuthJSONAccessTokenResponse);
        OAuthClientResponse oAuthClientResponse = Whitebox.invokeMethod(redditAuthenticator, "getOauthResponse",
                mockOAuthClient, mockOAuthClientRequest);
        return oAuthClientResponse;
    }
}
