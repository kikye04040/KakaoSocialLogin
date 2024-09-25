package com.sparta.kakaosociallogin.jwt;

import com.sparta.kakaosociallogin.dto.KakaoUserDetails;
import com.sparta.kakaosociallogin.entity.TokenType;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Base64;
import java.util.Date;

@Slf4j
@Component
public class JwtUtil {
    // Header KEY 값
    public static final String AUTHORIZATION_HEADER = "Authorization";
    // Token 식별자
    public static final String BEARER_PREFIX = "Bearer ";

    @Value("${jwt.secret.key}") // Base64 Encode 한 SecretKey
    private String secretKey;
    private Key key;
    private final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

    @PostConstruct
    public void init() {
        byte[] bytes = Base64.getDecoder().decode(secretKey);
        key = Keys.hmacShaKeyFor(bytes);
    }

    public String createKakaoToken(TokenType tokenType, KakaoUserDetails kakaoUserDetails) {
        long currentTimeMillis = System.currentTimeMillis();
        Date issuedAt = new Date(currentTimeMillis);
        Date expirationDate = new Date(currentTimeMillis + tokenType.getExpireMs());

        String token = Jwts.builder()
                .claim("category", tokenType.name().toLowerCase())
                .claim("email", kakaoUserDetails.getUsername()) // email 사용
                .claim("role", "ROLE_USER") // 기본 역할
                .setExpiration(expirationDate)
                .setIssuedAt(issuedAt)
                .signWith(key, signatureAlgorithm)
                .compact();

        return TokenType.ACCESS.equals(tokenType) ? BEARER_PREFIX + token : token;
    }
}
