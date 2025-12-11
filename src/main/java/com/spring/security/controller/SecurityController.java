package com.spring.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;

@RestController
//@RequestMapping("/security/v1")
public class SecurityController {

	@GetMapping("/")
	String displayHello(HttpServletRequest request) {
		return "Hello " + request.getSession().getId();
	}
	
}
