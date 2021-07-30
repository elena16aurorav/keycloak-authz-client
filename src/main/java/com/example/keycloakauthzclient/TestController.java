package com.example.keycloakauthzclient;

import lombok.RequiredArgsConstructor;
import org.keycloak.representations.AccessTokenResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class TestController {

    private final KeycloakService keycloakService;

    @GetMapping("/generate")
    public String generateToken() {
        return keycloakService.getTokenByPassword();
    }

    @GetMapping("/refresh")
    public String refreshToken() {
        return keycloakService.getTokenByRefreshToken();
    }

    @GetMapping("/actual-token")
    public String getActualToken() {
        return keycloakService.getActualAccessToken();
    }

    @GetMapping("/access-token")
    public String getAccessToken() {
        return KeycloakService.accessToken;
    }

    @GetMapping("/refresh-token")
    public String getRefreshToken() {
        return KeycloakService.refreshToken;
    }


}
