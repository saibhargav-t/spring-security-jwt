package com.spring.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.spring.security.service.UserDetailsServices;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

	private final UserDetailsServices userDetailsServices;
	private final JwtFilter jwtFilter;

	// INFO Method1
	SecurityFilterChain securityFilterChain1(HttpSecurity http) {
		return http.csrf(AbstractHttpConfigurer::disable).authorizeHttpRequests(req -> req
				.requestMatchers("/security/v1/register", "/security/v1/login")
				.permitAll()
				.anyRequest().authenticated())
				.formLogin(Customizer.withDefaults()).httpBasic(Customizer.withDefaults())
				.oauth2Login(Customizer.withDefaults())
				// INFO to five API access or allow postman to test API's.
				// .sessionManagement(session ->
				// session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				// INFO for browser to set state less we need to comment the formLogin.
				// INFO this only works in Postman with both formLogin and state less.
				.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
				.build();
	}

	// INFO Method2 You can choose any method to secure your API's.
	@Bean
	SecurityFilterChain securityFilterChain2(HttpSecurity http) throws Exception {
		return http.csrf(AbstractHttpConfigurer::disable)
				.authorizeHttpRequests(auth -> auth.requestMatchers("/security/v1/register", "/security/v1/login")
						.permitAll().anyRequest().authenticated())
				.formLogin(Customizer.withDefaults())
				.oauth2Login(oauth -> oauth.defaultSuccessUrl("/security/v1/home", true) // 👈
				// IMPORTANT
				).addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
				.logout(logout -> logout.logoutUrl("/logout").logoutSuccessUrl("/").invalidateHttpSession(true)
						.clearAuthentication(true).deleteCookies("JSESSIONID"))
				.build();
	}

	// @Bean
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
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsServices);
		provider.setPasswordEncoder(new BCryptPasswordEncoder());
		return provider;
	}

	@Bean
	BCryptPasswordEncoder bcryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	AuthenticationManager autenticationManager(AuthenticationConfiguration config) {
		return config.getAuthenticationManager();
	}
}
