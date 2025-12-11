package com.spring.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import com.spring.security.service.UserDetailsServices;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

	private final UserDetailsServices userDetailsServive;


	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) {
		return http.csrf(AbstractHttpConfigurer::disable).authorizeHttpRequests(req -> req.anyRequest().authenticated())
				.formLogin(Customizer.withDefaults()).httpBasic(Customizer.withDefaults())
				// INFO to five API access or allow postman to test API's.
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				// INFO for browser to set state less we need to comment the formLogin.
				// INFO this only works in Postman with both formLogin and state less.
				.build();
	}

	@Bean
	UserDetailsService userDetailsService() {
		UserDetails rama = User.builder().username("rama")
				.password("{bcrypt}$2a$10$xi6dHeKzA92oj0DauPfTFuCR60BxxKS25ePMk.Qj4tnCL6Ljd3Aly").roles("USER").build();
		UserDetails krishna = User.builder().username("krishna")
				.password("{bcrypt}$2a$10$0tgsX5yT2o2b2SmRQ4bSqut7lsqoxPnca4WHHCYXymkT7LArBxrWC").roles("ADMIN")
				.build();
		return new InMemoryUserDetailsManager(rama, krishna);
	}

	@Bean
	AuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsServive);
		provider.setPasswordEncoder(NoOpPasswordEncoder.getInstance());
		return provider;
	}
}
