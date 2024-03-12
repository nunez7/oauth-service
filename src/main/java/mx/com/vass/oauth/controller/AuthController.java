package mx.com.vass.oauth.controller;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import mx.com.vass.oauth.dto.TokenDto;
import mx.com.vass.oauth.dto.UserDto;
import mx.com.vass.oauth.service.AuthService;

@RestController
@RequestMapping("/auth")
public class AuthController {

	@Autowired
	private AuthService service;
	
	@PostMapping("/login")
	public ResponseEntity<TokenDto> login(@RequestBody UserDto user){
		return ResponseEntity.ok(service.login(user));
	}
	
	@PostMapping("/validate")
	public ResponseEntity<TokenDto> validate(@RequestParam String token){
		return ResponseEntity.ok(service.validate(token));
	}
	
	@PostMapping("/create")
	public ResponseEntity<UserDto> create(@RequestBody UserDto user){
		return ResponseEntity.ok(service.save(user));
	}
	
}