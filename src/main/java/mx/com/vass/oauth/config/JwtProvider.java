package mx.com.vass.oauth.config;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import mx.com.vass.oauth.entity.UserEntity;

import javax.crypto.SecretKey;

@Component
public class JwtProvider {
	private static final Logger LOGGER =  Logger.getLogger(JwtProvider.class.getName());

	@Value("${jwt.secret}")
	private String secret;
	
	SecretKey testKey = Jwts.SIG.HS256.key().build();
	
	public String createToken(UserEntity user) throws NoSuchAlgorithmException, InvalidKeySpecException {
		Map<String, Object> claims = new HashMap<>();
		claims.put("id", user.getId());
		claims.put("xaccount", "nunez7");

		Date now = new Date();
		Date exp = new Date(now.getTime() + 3600 * 1000);

		return Jwts.builder()
				.subject(user.getUsername())
				.header().add("company_name", "devs4j")
				.and().claims().add(claims)
				.and().issuedAt(now)
				.expiration(exp)
				.signWith(getKey(this.secret)).compact();
	}
	
	public SecretKey getKey(String secret) {
		byte[] secretBytes = secret.getBytes(StandardCharsets.UTF_8);
	    return Keys.hmacShaKeyFor(secretBytes);
	}

	public boolean validate(String token) throws JwtException, NoSuchAlgorithmException, InvalidKeySpecException {
		try {
			Jwts.parser().verifyWith(getKey(this.secret))
					.build()
					.parseSignedClaims(token)
					.getPayload();
			return true;
		}  catch (ExpiredJwtException e) {
			LOGGER.severe("token expired");
		} catch (UnsupportedJwtException e) {
			LOGGER.severe("token unsupported");
		} catch (MalformedJwtException e) {
			LOGGER.severe("token malformed");
		} catch (IllegalArgumentException e) {
			LOGGER.severe("illegal args");
		} 
        return false;
	}
	
	public String getUsernameFromToken(String token) {
		try {
			return Jwts.parser()
					.verifyWith(getKey(this.secret))
					.build()
					.parseSignedClaims(token)
					.getPayload()
					.getSubject();
		} catch (Exception e) {
			throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid token ");
		}
	}
	
}
