package mx.com.vass.oauth.service;

import org.springframework.stereotype.Service;

import mx.com.vass.oauth.dto.TokenDto;
import mx.com.vass.oauth.dto.UserDto;

@Service
public interface AuthService {
	public UserDto save(UserDto user);
	public TokenDto login(UserDto user);
	public TokenDto validate(String token);
}
