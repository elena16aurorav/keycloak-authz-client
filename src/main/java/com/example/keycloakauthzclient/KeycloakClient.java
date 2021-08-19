package com.example.keycloakauthzclient;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.client.HttpClient;
import org.keycloak.OAuth2Constants;
import org.keycloak.RSATokenVerifier;
import org.keycloak.adapters.HttpClientBuilder;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.authorization.client.Configuration;
import org.keycloak.authorization.client.util.Http;
import org.keycloak.common.VerificationException;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.KeysMetadataRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.CachePut;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.net.URL;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.example.keycloakauthzclient.CachingConfig.KEYCLOAK_TOKENS_CACHE;

@Slf4j
@Component
@RequiredArgsConstructor
public class KeycloakClient {

    @Value("${keycloak-authz-server.user.user1.login}")
    private String userLogin;

    @Value("${keycloak-authz-server.user.user1.password}")
    private String userPassword;

    @Value("${keycloak-authz-server.keycloak.exist}")
    private boolean iKeycloak;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.auth-server-url}")
    private String authServerUrl;

    @Value("${keycloak.resource}")
    private String clientId;

    @Value("${keycloak.credentials.secret}")
    private String clientSecret;

    public static final String CURRENT_TOKENS = "current_tokens";

    public org.keycloak.authorization.client.Configuration getKeyCloakConfig(){
//        Map<String, Object> credentials = getCredentials();

        HttpClient httpClient = new HttpClientBuilder().build();
//        Configuration configuration = new Configuration(authServerUrl, realm, clientId, credentials, httpClient);
        Configuration configuration = new Configuration();
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

    /**
     * receive new AccessToken and RefreshToken by username/password
     */
    @Cacheable(value=KEYCLOAK_TOKENS_CACHE, key = "#root.target.CURRENT_TOKENS")
    public AccessTokenResponse getTokenByPasswordCache(){
        log.info("getTokenByPasswordCache");
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
    //@CachePut(value=KEYCLOAK_TOKENS_CACHE, key = "#root.target.CURRENT_TOKENS")
    public AccessTokenResponse refreshTokenCache(String refreshToken) {
        log.info("refreshTokenCache");
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
//
    public AccessToken getAccessToken() {
        return getAccessToken(newKeycloakBuilderWithClientCredentials().build());
    }

    public String getAccessTokenString() {
        return getAccessTokenString(newKeycloakBuilderWithClientCredentials().build());
    }

    public AccessToken getAccessToken(String username, String password) {
        return getAccessToken(newKeycloakBuilderWithPasswordCredentials(username, password).build());
    }

    public String getAccessTokenString(String username, String password) {
        return getAccessTokenString(newKeycloakBuilderWithPasswordCredentials(username, password).build());
    }

    private AccessToken getAccessToken(Keycloak keycloak) {
        return extractAccessTokenFrom(keycloak, getAccessTokenString(keycloak));
    }

    private String getAccessTokenString(Keycloak keycloak) {
        AccessTokenResponse tokenResponse = getAccessTokenResponse(keycloak);
        return tokenResponse == null ? null : tokenResponse.getToken();
    }

    private AccessToken extractAccessTokenFrom(Keycloak keycloak, String token) {

        if (token == null) {
            return null;
        }

        try {
            RSATokenVerifier verifier = RSATokenVerifier.create(token);
            PublicKey publicKey = getRealmPublicKey(keycloak, verifier.getHeader());
            String realmUrl = authServerUrl + "/realms/" + realm;
            return verifier.realmUrl(realmUrl) //
                    .publicKey(publicKey) //
                    .verify() //
                    .getToken();
        } catch (VerificationException e) {
            return null;
        }
    }

    private KeycloakBuilder newKeycloakBuilderWithPasswordCredentials(String username, String password) {
        return newKeycloakBuilderWithClientCredentials() //
                .username(username) //
                .password(password) //
                .grantType(OAuth2Constants.PASSWORD);
    }

    private KeycloakBuilder newKeycloakBuilderWithClientCredentials() {
        return KeycloakBuilder.builder() //
                .realm(realm) //
                .serverUrl(authServerUrl)//
                .clientId(clientId) //
                .clientSecret(clientSecret) //
                .grantType(OAuth2Constants.CLIENT_CREDENTIALS);
    }

    private AccessTokenResponse getAccessTokenResponse(Keycloak keycloak) {
        try {
            return keycloak.tokenManager().getAccessToken();
        } catch (Exception ex) {
            return null;
        }
    }

    private PublicKey getRealmPublicKey(Keycloak keycloak, JWSHeader jwsHeader) {

// Variant 1: use openid-connect /certs endpoint
        return retrievePublicKeyFromCertsEndpoint(jwsHeader);

// Variant 2: use the Public Key referenced by the "kid" in the JWSHeader
// in order to access realm public key we need at least realm role... e.g. view-realm
//      return retrieveActivePublicKeyFromKeysEndpoint(keycloak, jwsHeader);

// Variant 3: use the active RSA Public Key exported by the PublicRealmResource representation
//      return retrieveActivePublicKeyFromPublicRealmEndpoint();
    }

    private PublicKey retrievePublicKeyFromCertsEndpoint(JWSHeader jwsHeader) {
        try {
            ObjectMapper om = new ObjectMapper();
            String realmCertsUrl = authServerUrl + "/realms/" + realm + "/protocol/openid-connect/certs";
            @SuppressWarnings("unchecked")
            Map<String, Object> certInfos = om.readValue(new URL(realmCertsUrl).openStream(), Map.class);

            List<Map<String, Object>> keys = (List<Map<String, Object>>) certInfos.get("keys");

            Map<String, Object> keyInfo = null;
            for (Map<String, Object> key : keys) {
                String kid = (String) key.get("kid");

                if (jwsHeader.getKeyId().equals(kid)) {
                    keyInfo = key;
                    break;
                }
            }

            if (keyInfo == null) {
                return null;
            }

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            String modulusBase64 = (String) keyInfo.get("n");
            String exponentBase64 = (String) keyInfo.get("e");

            // see org.keycloak.jose.jwk.JWKBuilder#rs256
            Base64.Decoder urlDecoder = Base64.getUrlDecoder();
            BigInteger modulus = new BigInteger(1, urlDecoder.decode(modulusBase64));
            BigInteger publicExponent = new BigInteger(1, urlDecoder.decode(exponentBase64));

            return keyFactory.generatePublic(new RSAPublicKeySpec(modulus, publicExponent));

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private PublicKey retrieveActivePublicKeyFromPublicRealmEndpoint() {

        try {
            ObjectMapper om = new ObjectMapper();
            String realmUrl = authServerUrl + "/realms/" + realm;
            @SuppressWarnings("unchecked")
            Map<String, Object> realmInfo = om.readValue(new URL(realmUrl).openStream(), Map.class);
            return toPublicKey((String) realmInfo.get("public_key"));
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    private PublicKey retrieveActivePublicKeyFromKeysEndpoint(Keycloak keycloak, JWSHeader jwsHeader) {

        List<KeysMetadataRepresentation.KeyMetadataRepresentation> keys =
                keycloak.realm(realm).keys().getKeyMetadata().getKeys();

        String publicKeyString = null;
        for (KeysMetadataRepresentation.KeyMetadataRepresentation key : keys) {
            if (key.getKid().equals(jwsHeader.getKeyId())) {
                publicKeyString = key.getPublicKey();
                break;
            }
        }

        return toPublicKey(publicKeyString);
    }

    public PublicKey toPublicKey(String publicKeyString) {
        try {
            byte[] publicBytes = Base64.getDecoder().decode(publicKeyString);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            return null;
        }
    }


}

