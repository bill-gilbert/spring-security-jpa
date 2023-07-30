package io.javabrains.springsecurityjpa;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Slf4j
@Service
public class JwtService {
    private String publicKey = "publicKey1234567890";
    private String privateKey = "privateKey1234567890";
    private Duration TTL = Duration.ofMinutes(2);

    public String extractUserId(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        JwtParser parser = null;
        try {
            byte[] bytes = Base64.getDecoder().decode(publicKey);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey publicKey = kf.generatePublic(spec);
            parser = Jwts.parserBuilder().setSigningKey(publicKey).build();
            return (Claims) parser.parse(token).getBody();
        }
        catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new RuntimeException(ex);
        }
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public String generateAccessToken(Integer partnerId, String partnerName) {
        var jwtToken = "";
        Map<String, Object> claims = new HashMap<>();
        claims.put("PartnerId", partnerId);
        claims.put("PartnerName", partnerName);

        try {
            byte[] bytes = Base64.getDecoder().decode(privateKey);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);

            //генерация валидных ключей
//          var keys = Keys.keyPairFor(SignatureAlgorithm.RS384);

            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = kf.generatePrivate(spec);
            jwtToken = Jwts.builder().setClaims(claims).setSubject(partnerName).setIssuedAt(new Date(System.currentTimeMillis()))
                    .setExpiration(new Date(System.currentTimeMillis() + TTL.toMillis()))
                    .signWith(privateKey, SignatureAlgorithm.RS384).compact();
        }
        catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new RuntimeException(ex);
        }

        return jwtToken;
    }

    public String getTokenSignature(String token) {
        return token.substring(token.lastIndexOf(".") + 1);
    }

    public boolean validateToken(String token, String partnerId, String ip) {
        /*
        if(isTokenExpired(token)) {
            return false;
        }

        var partnerEntity = partnerRepository.findById(Integer.parseInt(partnerId));
        AtomicBoolean result = new AtomicBoolean(false);
        partnerEntity.ifPresentOrElse(partner -> {
            if (partner.getToken().equals(token) && (checkUser(partner, ip))) {
                result.set(true);
            }
        }, () -> result.set(false));

         */

        // return result.get();
        //MOCK
        return true;
    }

//    public Boolean validateRefreshToken(String token) {
//        Integer userId = Integer.parseInt(extractUserId(token));
//        return refreshSessionService.validateRefreshToken(userId, getTokenSignature(token));
//    }


//    public boolean checkUser(PartnerEntity partnerEntity, String ip) {
//        return !partnerEntity.isCheckIp() || (ip.equals(partnerEntity.getIp1()) || ip.equals(partnerEntity.getIp2()));
//    }
}
