package com.spring.security.service;

import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {

	private final JwtService jwtService;

	public String generateToken(String username) {
		return jwtService.generateToken(username);
	}

	
}
