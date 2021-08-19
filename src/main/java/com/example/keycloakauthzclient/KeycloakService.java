package com.example.keycloakauthzclient;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.representations.AccessTokenResponse;
import org.springframework.cache.CacheManager;
import org.springframework.stereotype.Service;
import com.auth0.jwt.JWT;

import java.time.LocalDateTime;

import static com.example.keycloakauthzclient.CachingConfig.KEYCLOAK_TOKENS_CACHE;
import static com.example.keycloakauthzclient.DateUtils.convertLocalDateTimeToDate;
import static com.example.keycloakauthzclient.KeycloakClient.CURRENT_TOKENS;

@RequiredArgsConstructor
@Service
@Slf4j
public class KeycloakService {

    private final KeycloakClient keyCloakClient;
    private final CacheManager cacheManager;

    public static String accessToken;
    public static String refreshToken;

    //сохранение токенов в статических переменных
    public String getActualAccessTokenStatic(){
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

    //сохранение токенов с помощью кеширования
    public String getActualAccessTokenCache(){
        AccessTokenResponse accessTokenResponse = keyCloakClient.getTokenByPasswordCache();
        if(isExpired(accessTokenResponse.getToken())){//accessToken is not actual
            if(isExpired(accessTokenResponse.getRefreshToken())){//refreshToken is not actual
                log.info("Истекло время жизни refreshToken. Получение токенов по паролю");
                evictCachedToken();
                getActualAccessTokenCache();
            }else{//refreshToken is actual
                log.info("Истекло время жизни accessToken. Получение токенов по refreshToken");
                evictCachedToken();
                accessTokenResponse = keyCloakClient.refreshTokenCache(accessTokenResponse.getRefreshToken());
                var cache = cacheManager.getCache(KEYCLOAK_TOKENS_CACHE);
                cache.put(CURRENT_TOKENS, accessTokenResponse);
            }
        }
        log.info("Текущие значения: accessToken="+accessTokenResponse.getToken()
                +"; refreshToken="+accessTokenResponse.getRefreshToken());
        return accessTokenResponse.getToken();
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

    private void evictCachedToken(){
        var cache = cacheManager.getCache(KEYCLOAK_TOKENS_CACHE);
        if(null == cache){
            log.error("empty cache");
        }else{
            cache.clear();
        }
    }

    public String getTokenByRefreshToken(){
        AccessTokenResponse response = keyCloakClient.refreshToken(refreshToken);
        accessToken = response.getToken();
        refreshToken = response.getRefreshToken();
        return "accessToken="+accessToken+"; refreshToken="+refreshToken;
    }
}
