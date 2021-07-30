package com.example.keycloakauthzclient;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.representations.AccessTokenResponse;
import org.springframework.cache.CacheManager;
import org.springframework.stereotype.Service;
import com.auth0.jwt.JWT;

import java.time.LocalDateTime;

import static com.example.keycloakauthzclient.DateUtils.convertLocalDateTimeToDate;

@RequiredArgsConstructor
@Service
@Slf4j
public class KeycloakService {

    private final KeycloakClient keyCloakClient;
    private final CacheManager cacheManager;

    public static String accessToken;
    public static String refreshToken;

    public String getActualAccessToken(){
        if(accessToken == null){
            log.info("Получение токенов по паролю");
            AccessTokenResponse accessTokenResponse = keyCloakClient.getTokenByPassword();
            accessToken = accessTokenResponse.getToken();
            refreshToken = accessTokenResponse.getRefreshToken();
        }else{
            if(isExpired(accessToken)){//accessToken is not actual
                if(isExpired(refreshToken)){//refreshToken is not actual
                    log.info("Истекло время жизни refreshToken. Получение токенов по паролю");
                    AccessTokenResponse accessTokenResponse = keyCloakClient.getTokenByPassword();
                    accessToken = accessTokenResponse.getToken();
                    refreshToken = accessTokenResponse.getRefreshToken();
                }else{//refreshToken is actual
                    log.info("Истекло время жизни accessToken. Получение токенов по refreshToken");
                    AccessTokenResponse accessTokenResponse = keyCloakClient.refreshToken(refreshToken);
                    accessToken = accessTokenResponse.getToken();
                    refreshToken = accessTokenResponse.getRefreshToken();
                }
            }
        }
        log.info("Текущие значения: accessToken="+accessToken+"; refreshToken="+refreshToken);
        return accessToken;
    }

    /**
     * определение актуальности токена
     * @param token
     * @return
     */
    public boolean isExpired(String token){
        var decodedJWT = JWT.decode(token);
        return decodedJWT.getExpiresAt().before(convertLocalDateTimeToDate(LocalDateTime.now().minusMinutes(1)));
    }

    public String getTokenByPassword(){
        AccessTokenResponse response = keyCloakClient.getTokenByPassword();
        accessToken = response.getToken();
        refreshToken = response.getRefreshToken();
        return "accessToken="+accessToken+"; refreshToken="+refreshToken;
    }

    public String getTokenByRefreshToken(){
        AccessTokenResponse response = keyCloakClient.refreshToken(refreshToken);
        accessToken = response.getToken();
        refreshToken = response.getRefreshToken();
        return "accessToken="+accessToken+"; refreshToken="+refreshToken;
    }

    private void evictCachedToken(){
        var cache = cacheManager.getCache("token");

        if(null == cache){
            log.error("empty cache");
        }else{
            cache.clear();
        }
    }

}
