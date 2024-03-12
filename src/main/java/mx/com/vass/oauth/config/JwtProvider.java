package mx.com.vass.oauth.config;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
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
	
	public String createToken(UserEntity user) {
		Map<String, Object> claims = new HashMap<>();
		claims.put("id", user.getId());
		claims.put("twitter_account", "@raidentrance");

		Date now = new Date();
		Date exp = new Date(now.getTime() + 3600 * 1000);

		return Jwts.builder()
				.header().add("company_name", "devs4j")
				.and().claims().empty().add(claims)
				.and().issuedAt(now)
				.expiration(exp)
				.signWith(getKey(this.secret)).compact();
	}

	private SecretKey getKey(String secret) {
		byte[] secretBytes = Decoders.BASE64URL.decode(secret);
		return Keys.hmacShaKeyFor(secretBytes);
	}

	public boolean validate(String token) {
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

	public Claims getClaims(String token) {
		return Jwts.parser()
				.verifyWith(getKey(this.secret))
				.build()
				.parseSignedClaims(token)
				.getPayload();
	}
	
}
