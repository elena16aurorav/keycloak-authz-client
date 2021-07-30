package com.example.keycloakauthzclient;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.client.HttpClient;
import org.keycloak.adapters.HttpClientBuilder;
import org.keycloak.authorization.client.Configuration;
import org.keycloak.authorization.client.util.Http;
import org.keycloak.representations.AccessTokenResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class KeycloakClient {

    @Value("${keycloak-authz-server.user.login}")
    private String userLogin;

    @Value("${keycloak-authz-server.user.password}")
    private String userPassword;

    @Value("${keycloak-authz-server.exist}")
    private boolean iKeycloak;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.auth-server-url}")
    private String authServerUrl;

    @Value("${keycloak.resource}")
    private String clientId;

    @Value("${keycloak.credentials.secret}")
    private String clientSecret;

    public static String accessToken;
    public static String refreshToken;

    //@Bean
    public org.keycloak.authorization.client.Configuration getKeyCloakConfig(){
        Map<String, Object> credentials = getCredentials();

        HttpClient httpClient = new HttpClientBuilder().build();
        Configuration configuration = new Configuration(authServerUrl, realm, clientId, credentials, httpClient);
        if(configuration == null){
            log.error("Не удалось подключиться к серверу KeyCloak!!!");
            //
        }
        return configuration;
    }

    public Map<String, Object> getCredentials(){
        Map<String, Object> credentials = new HashMap<>();
        if (clientSecret == null) {
            credentials.put("secret", clientSecret);
        }
        else{
            credentials.put("secret", "");
        }
        return credentials;
    }

    /**
     * receive new AccessToken and RefreshToken by username/password
     */
    public AccessTokenResponse getTokenByPassword(){
        String url = authServerUrl + "/realms/" + realm + "/protocol/openid-connect/token";

        Http http = new Http(getKeyCloakConfig(), (params, headers) -> {});
        return http.<AccessTokenResponse>post(url)
                .authentication()
                .client()
                .form()
                .param("grant_type", "password")
                .param("client_id", clientId)
                .param("client_secret", clientSecret)
                .param("username", userLogin)
                .param("password", userPassword)
                .response()
                .json(AccessTokenResponse.class)
                .execute();
    }

    /**
     * Receive new AccessToken and RefreshToken by OldRefreshToken
     * @param refreshToken
     */
    public AccessTokenResponse refreshToken(String refreshToken) {
        String url = authServerUrl + "/realms/" + realm + "/protocol/openid-connect/token";

        Http http = new Http(getKeyCloakConfig(), (params, headers) -> {});
        return http.<AccessTokenResponse>post(url)
                .authentication()
                .client()
                .form()
                .param("grant_type", "refresh_token")
                .param("refresh_token", refreshToken)
                .param("client_id", clientId)
                .param("client_secret", (String) getCredentials().get("secret"))
                .response()
                .json(AccessTokenResponse.class)
                .execute();
    }

}

