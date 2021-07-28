package com.example.keycloakauthzclient;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class TestController {

    private final KeyCloakClient keyCloakClient;

    @GetMapping("/generate")
    public String generateToken() {
        String token = keyCloakClient.getAccessToken();
        return token;
    }

    @GetMapping("/validate")
    public String validateToken() {
        return "private";
    }

    @GetMapping("/publickey")
    public String getPublicKey() {
        return "private";
    }


}
