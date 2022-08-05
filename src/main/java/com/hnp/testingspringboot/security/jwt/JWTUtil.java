package com.hnp.testingspringboot.security.jwt;

import com.hnp.testingspringboot.entity.User;
import com.hnp.testingspringboot.model.TokenStore;
import com.hnp.testingspringboot.redisrepo.TokenStoreRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.temporal.TemporalUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Component
public class JWTUtil {

    private static final int EXPIRE_MINUTES = 1;

    @Value("${securiry.jwt.secret}")
    private String secretKey;

    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    @Autowired
    private TokenStoreRepository tokenStoreRepository;


    public String generateToken(User user) {
        return getTokenStore(user).map(TokenStore::getToken)
                .orElse(claimNewToken(user));
    }

    private String claimNewToken(final User user) {
        final Map<String, Object> claims = new HashMap<>();
        final Date expireDate = Date.from(LocalDateTime.now().plusMinutes(EXPIRE_MINUTES).atZone(ZoneId.systemDefault()).toInstant());
        final String token = Jwts.builder().setClaims(claims).setSubject(user.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(expireDate)
                .signWith(SignatureAlgorithm.HS512, secretKey).compact();

        final TokenStore newTokenStore = new TokenStore();
        newTokenStore.setToken(token);
        newTokenStore.setUsername(user.getUsername());
        newTokenStore.setExpireDate(expireDate);

        this.tokenStoreRepository.save(newTokenStore);

        return token;
    }

    public boolean validateToken(TokenStore tokenStore) {
        try {
            Jwts.parser().setSigningKey(secretKey).parseClaimsJws(tokenStore.getToken());
            return getExpireDateFromToken(tokenStore.getToken()).after(new Date());
        } catch (Exception e) {
            return false;
        }
    }

    public boolean validateTokenForAccess(String token) {
        return this.tokenStoreRepository.findById(token)
                .map(this::validateToken)
                .orElse(false);
    }

    public String getUsernameFromToken(String token) {
        return getClaims(token).getSubject();
    }

    public Date getExpireDateFromToken(String token) {
        return getClaims(token).getExpiration();
    }

    public Claims getClaims(String token) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();
    }

    public Optional<TokenStore> getTokenStore(User user) {
        return tokenStoreRepository.findByUsername(user.getUsername())
                .filter(this::validateToken)
                .map(tokenStore -> {
                    tokenStoreRepository.deleteById(tokenStore.getToken());
                    return null;
                });
    }
}
