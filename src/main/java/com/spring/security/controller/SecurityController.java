
package com.spring.security.controller;

import org.jspecify.annotations.Nullable;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.spring.security.model.Users;
import com.spring.security.service.AuthService;
import com.spring.security.service.UserDetailsServices;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/security/v1")
@RequiredArgsConstructor
@Slf4j
public class SecurityController {

	private final UserDetailsServices services;
	private final BCryptPasswordEncoder bcrypt;
	private final AuthService service;
	private final AuthenticationManager manager;

	@GetMapping("/")
	String displayHello(HttpServletRequest request) {
		return "Hello " + request.getSession().getId();
	}

	@PostMapping("/register")
	String registerUser(@RequestBody Users users) {
		@Nullable
		String encode = bcrypt.encode(users.getPassword());
		users.setPassword(encode);
		services.registerUser(users);
		log.info("Saving user to database: {}", users.getUsername());
		return users.getUsername() + " Registered successfully..";
	}
	
	@PostMapping("/login")
    public String login(@RequestBody Users users) {
        Authentication auth = manager.authenticate(
            new UsernamePasswordAuthenticationToken(
                users.getUsername(),
                users.getPassword()
            )
        );

        return auth.isAuthenticated()
                ? service.generateToken(users.getUsername())
                : "Failure";
    }
	
	@GetMapping("/home")
	public String home() {
	    return "Logged in successfully";
	}
}

