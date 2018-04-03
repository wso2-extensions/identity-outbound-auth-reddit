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

public class RedditAuthenticatorConstants {
    //Reddit Authenticator name
    public static final String AUTHENTICATOR_NAME = "Reddit";
    //Reddit Authenticator friendly name
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "RedditAuthenticator";
    //Reddit authorize endpoint URL
    public static final String REDDIT_OAUTH_ENDPOINT = "https://www.reddit.com/api/v1/authorize";
    //Reddit token  endpoint URL
    public static final String REDDIT_TOKEN_ENDPOINT = "https://www.reddit.com/api/v1/access_token";
    //Reddit user info endpoint URL
    public static final String REDDIT_USERINFO_ENDPOINT = "https://oauth.reddit.com/api/v1/me";
    //Reddit user info scope
    public static final String SCOPE = "scope";
    //Reddit identity scope for user info
    public static final String USER_SCOPE = "identity";
    //Reddit user id
    public static final String USER_ID = "id";
    //Reddit GET request
    public static final String HTTP_GET = "GET";
    //Reddit Authorization header
    public static final String AUTHORIZATION = "Authorization";
    //Reddit Bearer Authorization
    public static final String AUTHORIZATION_BEARER = "Bearer ";
    //Reddit Basic Authorization
    public static final String AUTHORIZATION_BASIC = "Basic ";
    //Reddit contentType
    public static final String CONTENT_TYPE = "Content-Type";
    //Reddit json contentType
    public static final String CONTENT_TYPE_JSON = "application/json";
    //Request_host_header
    public static final String REQUEST_HOST_HEADER = "REQUEST_HOST_HEADER";
    //Reddit host
    public static final String REDDIT_HOST = "host";
    //Reddit authorization code
    public static final String CODE = "code";
    //Reddit authorization header for User_Agent
    public static final String REDDIT_USER_AGENT = "User-Agent";
    //Reddit value for User_Agent header
    public static final String USER_AGENT = "USER_AGENT";
    //Reddit value for Client id
    public static final String REDDIT_CLIENT_ID = "Client Id";
    //Reddit value for Client secret
    public static final String REDDIT_CLIENT_SECRET = "Client Secret";
    //Reddit value for Callback_url
    public static final String REDDIT_CALLBACK_URL = "Callback URL";
    public static final String OAUTH2_PARAM_ERROR = "error";
    public static final String ERROR = "error: ";
    public static final String STATE = ", state: ";
}
