package com.example.keycloakauthzclient;

import lombok.SneakyThrows;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.Configuration;
import org.springframework.beans.factory.annotation.Value;
import org.apache.http.client.HttpClient;
import org.keycloak.adapters.HttpClientBuilder;
import org.keycloak.authorization.client.AuthzClient;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.context.annotation.Bean;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;


@org.springframework.context.annotation.Configuration
public class KeyCloakConfig {

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

    @Bean
    public AuthzClient getAuthzClient(){
        if(!iKeycloak){
            return null;
        }

        Configuration authzConfig = getAuthzConfig();
        AuthzClient authzClient = AuthzClient.create(authzConfig);
        return authzClient;
    }

    @SneakyThrows
    public Configuration getAuthzConfig(){
        Map<String, Object> credentials = new HashMap<>();
        if (clientSecret == null) {
            credentials.put("secret", clientSecret);
        }
        else{
            credentials.put("secret", "");
        }

        Configuration configuration = new Configuration(authServerUrl, realm, clientId, credentials, getHttpClient());
        if(configuration == null){
            throw new Exception("Не удалось подключиться к серверу KeyCloak!!!");
        }
        return configuration;
    }

    public HttpClient getHttpClient(){
        int conTimeout = 10;
        int socTimeout = 10;
        HttpClient client = new HttpClientBuilder()
                //.establishConnectionTimeout(conTimeout, TimeUnit.MILLISECONDS)
                //.socketTimeout(socTimeout, TimeUnit.MILLISECONDS)
                .build();//Interface AdapterHttpClientConfig

        return client;
    }
}
