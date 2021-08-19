package com.example.keycloakauthzclient;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;

@SpringBootApplication
@EnableCaching
public class KeycloakAuthzClientApplication {

    public static void main(String[] args) {
        SpringApplication.run(KeycloakAuthzClientApplication.class, args);
    }

}
