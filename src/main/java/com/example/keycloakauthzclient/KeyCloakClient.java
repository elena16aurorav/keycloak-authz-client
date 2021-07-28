package com.example.keycloakauthzclient;

import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.keycloak.authorization.client.AuthzClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
@org.springframework.context.annotation.Configuration
@RequiredArgsConstructor
public class KeyCloakClient {

    @Value("${keycloak-authz-server.user.login}")
    private String userLogin;

    @Value("${keycloak-authz-server.user.password}")
    private String userPassword;

    private final KeyCloakConfig keyCloakConfig;

    @SneakyThrows
    public String getAccessToken() {
        try {
            AuthzClient authzClient = keyCloakConfig.getAuthzClient();
            String token = authzClient.obtainAccessToken(userLogin, userPassword).getToken();
            return token;
        }
        catch(Exception ex){
            throw new Exception("Ошибка при получении токена!!!");
        }
    }
}

