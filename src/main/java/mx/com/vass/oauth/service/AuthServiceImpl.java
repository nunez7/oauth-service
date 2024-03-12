package mx.com.vass.oauth.service;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Optional;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import io.jsonwebtoken.JwtException;
import mx.com.vass.oauth.config.JwtProvider;
import mx.com.vass.oauth.dto.TokenDto;
import mx.com.vass.oauth.dto.UserDto;
import mx.com.vass.oauth.entity.UserEntity;
import mx.com.vass.oauth.repository.UserRepository;

@Service
public class AuthServiceImpl implements AuthService{
	
	@Autowired
	private UserRepository userRepository;

	@Autowired
	private PasswordEncoder encoder;

	@Autowired
	private JwtProvider jwtProvider;

	@Autowired
	private ModelMapper mapper;

	@Override
	public UserDto save(UserDto user) {
		Optional<UserEntity> response = userRepository.findByUsername(user.getUsername());
		if (response.isPresent()) {
			throw new ResponseStatusException(HttpStatus.CONFLICT,
					String.format("User %s already exist", user.getUsername()));
		}
		UserEntity entity = userRepository.save(new UserEntity(user.getUsername(), encoder.encode(user.getPassword())));
		return mapper.map(entity, UserDto.class);
	}

	@Override
	public TokenDto login(UserDto user) {
		UserEntity userEntity = userRepository.findByUsername(user.getUsername())
				.orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED));
		if (encoder.matches(user.getPassword(), userEntity.getPassword())) {
			try {
				return new TokenDto(jwtProvider.createToken(userEntity));
			} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} else {
			throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
		}
		return null;
	}

	@Override
	public TokenDto validate(String token) {
		try {
			jwtProvider.validate(token);
			String username = jwtProvider.getUsernameFromToken(token);
			userRepository.findByUsername(username).orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED));
			return new TokenDto(token);
		} catch (JwtException | NoSuchAlgorithmException | InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
	}

}
