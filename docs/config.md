# Configuring Reddit Authenticator

 This page provides instructions on how to configure the Reddit authenticator and Identity Server using a sample app. You can find more information in the following sections.
 ````
This is tested for the Reddit API version 1.0.
 ````
 
* [Deploying Reddit artifacts](#deploying-reddit-artifacts)
* [Configuring the Reddit App](#configuring-the-reddit-app)
* [Deploying travelocity.com Sample App](#deploying-travelocitycom-sample-app)
* [Configuring the identity provider](#configuring-the-identity-provider)
* [Configuring the service provider](#configuring-the-service-provider)
* [Testing the sample](#testing-the-sample)

### Deploying Reddit artifacts
 * Download the WSO2 Identity Server from [here](https://wso2.com/identity-and-access-management).
 * Download the Reddit authenticator from [here](https://store.wso2.com/store/assets/isconnector/details/45092602-8b7b-4f29-9d66-cc5b39990907) and add it to the <IS_HOME>/repository/components/dropins directory.

 >> NOTE :If you want to upgrade the Reddit Authenticator (.jar) in your existing IS pack, please refer [upgrade instructions](https://docs.wso2.com/display/ISCONNECTORS/Upgrading+an+Authenticator).

### Configuring the Reddit App
 1. Create a reddit account using the URL [https://www.reddit.com/](https://www.reddit.com/) and log in.
     
 2. Navigate to [https://www.reddit.com/prefs/apps](https://www.reddit.com/prefs/apps) and click **are you a developer?create an app** on the top left corner.
    Example:

    ![alt text](images/app.png)
 3. Create a web app.
    Use [https://localhost:9443/commonauth](https://localhost:9443/commonauth) as the **about url** and **redirect uri** when creating the web app.

    ![alt text](images/redd.png)
 4. Now you can get the clientId and clientSecret of your created app.

    ![alt text](images/red2.png)

### Deploying [travelocity.com](https://www.travelocity.com/) Sample App
    
   The next step is to [deploy the sample app](sampleApp.md) in order to use it in this scenario.

   Once this is done, the next step is to configure the WSO2 Identity Server by adding a [service provider](https://docs.wso2.com/display/IS530/Adding+and+Configuring+a+Service+Provider) and an [identity provider](https://docs.wso2.com/display/IS530/Adding+and+Configuring+an+Identity+Provider).

### Configuring the identity provider
Now you have to configure WSO2 Identity Server by adding a [new identity provider](https://docs.wso2.com/display/IS530/Adding+and+Configuring+an+Identity+Provider).
 1. Go to [https://www.reddit.com/](https://www.reddit.com/) in your browser, and click the HTTPS trust icon on the address bar (e.g., the padlock next to the URL in Chrome) to download the certificate.
    Based on the  browser the steps to download the certificate changes. Click valid under Certificate (Chrome) or click Show certificate (Safari), expand the **Details** section and click the URL under CA Issuer to download the certificate.
    Example: On Chrome

    ![alt text](images/cert.png)


    >> This is supported on Firefox and Safari browsers by default but it is not supported on some Chrome browsers.

        Following are the steps to know how to enable certificate downloading on Chrome.

            a. Navigate to chrome://flags/#show-cert-link.

            b. Click Enable to view the certificates.


    ![alt text](images/enable.png)

            c . Relaunch Chrome.
 2. Import that certificate into the IS client keystore.

    keytool -importcert -file <certificate_file> -keystore <IS>/repository/resources/security/client-truststore.jks -alias "Reddit"

    ```
    The default password of the client-truststore.jks is "wso2carbon".
    ```

 3. Run the [WSO2 Identity Server](https://docs.wso2.com/display/IS530/Running+the+Product).
 4. Log in to the [management console](https://docs.wso2.com/display/IS530/Getting+Started+with+the+Management+Console) as an administrator.
 5. In the **Identity Providers** section under the **Main** tab of the management console, click **Add**.
 6. Give a suitable name for **Identity Provider Name**.

    ![alt text](images/identity.png)
 7. Navigate to **RedditAuthenticator Configuration** under **Federated Authenticators**.
 8. Enter the values as given in the above figure.
    * **Client Id:** Client Id for your app.
    * **Client Secret:**  Client Secret for your app.
    * **Callback Url:** Service Provider's URL where code needs to be sent (https://localhost:9443/commonauth).
 9. Select both checkboxes to **Enable** the Reddit authenticator and make it the **Default**.
 10. Click **Register**.

You have now added the identity provider.

### Configuring the service provider
The next step is to configure the service provider.
 1. Return to the management console.
 2. In the **Service Providers** section, click **Add** under the **Main** tab.
 3. Since you are using travelocity as the sample, enter [travelocity.com](https://www.travelocity.com/) in the **Service Provider Name** text box and click **Register**.
 4. In the **Inbound Authentication Configuration** section, click **Configure** under the **SAML2 Web SSO Configuration** section.
 5. Now set the configuration as follows:
    * **Issuer:** travelocity.com
    * **Assertion Consumer URL:**  http://localhost:8080/travelocity.com/home.jsp
 6. Select the following check-boxes:
    * **Enable Response Signing**.
    * **Enable Single Logout**.
    * **Enable Attribute Profile**.
    * **Include Attributes in the Response Always**.

        ![alt text](images/serviceProvider.png)
 7. Click **Update** to save the changes. Now you will be sent back to the **Service Providers** page.
 8. Navigate to the **Local and Outbound Authentication Configuration** section.
 9. Select the identity provider you created from the dropdown list under **Federated Authentication**.

    ![alt text](images/service.png)

 10. Ensure that the **Federated Authentication** radio button is selected and click Update to save the changes.

You have now added and configured the service provider.

### Testing the sample
 
 1. To test the sample, go to the following URL: http://<TOMCAT_HOST>:<TOMCAT_PORT>/travelocity.com/index.jsp . E.g., http://localhost:8080/travelocity.com
 2. Login with SAML(Redirect binding) from the WSO2 Identity Server.

    ![alt text](images/travelocity.png)
 3. Enter your Reddit credentials in the prompted login page of Reddit. Once you log in successfully you will be taken to the home page of the travelocity.com app.
