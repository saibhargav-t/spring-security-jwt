# Spring Security Tutorial

This document provides a comprehensive tutorial on Spring Security, covering various authentication mechanisms and integration with JWT for securing your Spring Boot applications.

## 1. Introduction to Spring Security

Spring Security is a powerful and highly customizable authentication and access-control framework. It is the de-facto standard for securing Spring-based applications.

The primary goal of Spring Security is to provide authentication and authorization to Java applications.

* **Authentication**: The process of verifying who a user is.
* **Authorization**: The process of deciding if a user is allowed to do something.

### Core Concepts

Spring Security is based on Servlet Filters. When a request comes to a web application, it goes through a chain of filters. Spring Security installs its own set of filters to handle security-related concerns.

* `SecurityFilterChain`: A filter chain that is applied to HTTP requests. You can have multiple security filter chains, each for different parts of your application.
* `AuthenticationManager`: The main strategy interface for authentication. If it can'tauthenticate a request, it will throw an `AuthenticationException`.
* `UserDetailsService`: An interface to load user-specific data. It is used by the `AuthenticationManager` to retrieve user details (username, password, authorities).
* `PasswordEncoder`: An interface for encoding passwords.

## 2. The Spring Security Filter Chain

When a request is made to a Spring application secured by Spring Security, it passes through a chain of filters before it reaches the servlet or controller. Each filter has a specific responsibility. Understanding this chain is key to customizing Spring Security.

The filters are ordered, and here are some of the most important ones in their typical order:

1. **`SecurityContextPersistenceFilter`**: Populates the `SecurityContextHolder` with a `SecurityContext` from the `HttpSession` for the current request. At the end of the request, it clears the `SecurityContextHolder` and saves any changes to the `HttpSession`.
2. **`HeaderWriterFilter`**: Adds security-related headers to the response (e.g., `X-Frame-Options`, `X-XSS-Protection`, `X-Content-Type-Options`).
3. **`CsrfFilter`**: Protects against Cross-Site Request Forgery attacks by inspecting a CSRF token.
4. **`LogoutFilter`**: Intercepts logout requests (by default at `/logout`) and logs the user out.
5. **`UsernamePasswordAuthenticationFilter`**: The default filter for processing form-based login submissions. It authenticates the username and password from the request.
6. **`DefaultLoginPageGeneratingFilter`**: If no other filter handles a login request, this filter generates a default login page.
7. **`BasicAuthenticationFilter`**: Processes HTTP Basic authentication headers.
8. **`RequestCacheAwareFilter`**: Uses a `RequestCache` to re-create a saved request after successful authentication (e.g., redirecting the user to the page they originally tried to access).
9. **`SecurityContextHolderAwareRequestFilter`**: Wraps the `HttpServletRequest` to provide access to the `SecurityContext` for methods like `isUserInRole()`.
10. **`AnonymousAuthenticationFilter`**: If no authentication is present in the `SecurityContextHolder`, this filter creates an anonymous `Authentication` object.
11. **`SessionManagementFilter`**: Manages session-related activities, including session fixation protection and concurrent session control.
12. **`ExceptionTranslationFilter`**: Catches Spring Security exceptions (like `AccessDeniedException`) and handles them, typically by starting an authentication process or returning a 403 Forbidden error.
13. **`FilterSecurityInterceptor`**: The final filter in the chain. It performs authorization, checking if the authenticated user has the necessary permissions to access the requested resource. If not, it throws an `AccessDeniedException`.

You can add your own custom filters at specific points in this chain. For example, the `JwtRequestFilter` we discuss later is typically added before the `UsernamePasswordAuthenticationFilter`.

## 3. Securing Web Resources

The most common way to configure Spring Security is by extending `WebSecurityConfigurerAdapter` (in older versions) or by defining a `SecurityFilterChain` bean (the modern approach).

Here is a basic security configuration:

```java
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorizeRequests ->
                authorizeRequests
                    .requestMatchers("/public/**").permitAll() // Allow public access
                    .anyRequest().authenticated() // All other requests need authentication
            )
            .formLogin(formLogin ->
                formLogin
                    .loginPage("/login") // Custom login page
                    .permitAll()
            )
            .logout(logout ->
                logout
                    .logoutUrl("/logout")
                    .permitAll()
            );
        return http.build();
    }
}
```

## 4. Authentication Mechanisms

Spring Security offers several ways to manage user credentials.

### 4.1. In-Memory Authentication

This method is useful for testing and small applications where user details are stored in memory.

```java
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class InMemoryAuthSecurityConfig {

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.builder()
            .username("user")
            .password(passwordEncoder().encode("password"))
            .roles("USER")
            .build();
        UserDetails admin = User.builder()
            .username("admin")
            .password(passwordEncoder().encode("admin"))
            .roles("ADMIN", "USER")
            .build();
        return new InMemoryUserDetailsManager(user, admin);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

### 4.2. Using `application.properties`

You can define a single user in your `application.properties` file. This is the simplest way to get started.

```properties
# application.properties
spring.security.user.name=user
spring.security.user.password=password
spring.security.user.roles=USER
```

**Note:** The password here is in plain text, which is not secure for production.

### 4.3. Database Authentication (JDBC)

For most production applications, user details are stored in a database. Spring Security can easily connect to a database using JDBC.

**1. Schema:** You need tables for users and their authorities.

```sql
CREATE TABLE users (
    username VARCHAR(50) NOT NULL PRIMARY KEY,
    password VARCHAR(100) NOT NULL,
    enabled BOOLEAN NOT NULL
);

CREATE TABLE authorities (
    username VARCHAR(50) NOT NULL,
    authority VARCHAR(50) NOT NULL,
    FOREIGN KEY (username) REFERENCES users (username)
);
```

**2. Configuration:** Configure a `JdbcUserDetailsManager`.

```java
import javax.sql.DataSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class JdbcAuthSecurityConfig {

    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
        return new JdbcUserDetailsManager(dataSource);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

You also need to configure the `DataSource` in your `application.properties`.

## 5. Login Form

### 5.1. Default Login Form

If you don't specify a custom login form, Spring Security provides a default one at `/login`. It's basic but functional.

### 5.2. Custom Login Form

To use your own login form, you need to:

1. Create an HTML file for the login page.
2. Configure Spring Security to use it.

**login.html (in `src/main/resources/templates/`)**

```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Login</title>
</head>
<body>
    <h1>Login</h1>
    <div th:if="${param.error}">
        Invalid username and password.
    </div>
    <div th:if="${param.logout}">
        You have been logged out.
    </div>
    <form th:action="@{/login}" method="post">
        <div><label> User Name : <input type="text" name="username"/> </label></div>
        <div><label> Password: <input type="password" name="password"/> </label></div>
        <div><input type="submit" value="Sign In"/></div>
    </form>
</body>
</html>
```

**Security Configuration:**

```java
@Configuration
@EnableWebSecurity
public class CustomLoginSecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login") // Specify the custom login page URL
                .permitAll()
            );
        return http.build();
    }
    // ... other beans like UserDetailsService, PasswordEncoder
}
```

You'll also need a controller to show the login page.

```java
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AuthController {

    @GetMapping("/login")
    public String login() {
        return "login";
    }
}
```

## 6. Session Management in Spring Security

By default, Spring Security creates and manages a standard `HttpSession` for authenticated users. This is a stateful approach where the server stores session information between requests.

### How Sessions Work

When a user authenticates successfully, Spring Security creates a `SecurityContext` containing the `Authentication` object. This `SecurityContext` is then stored in the `HttpSession`. For subsequent requests, the `SecurityContextPersistenceFilter` retrieves the `SecurityContext` from the session and populates the `SecurityContextHolder`, making it available throughout the request.

### Session Creation Policies

You can control when Spring Security creates sessions using the `sessionCreationPolicy()` method.

```java
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SessionManagementSecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) // This is the default
            );
        return http.build();
    }
}
```

The available policies are:

* `SessionCreationPolicy.ALWAYS`: A session will always be created if one doesn't already exist.
* `SessionCreationPolicy.IF_REQUIRED`: (Default) A session will be created only if it's needed (e.g., after a successful authentication).
* `SessionCreationPolicy.NEVER`: Spring Security will never create a session itself, but it will use one if it already exists (e.g., created by the application).
* `SessionCreationPolicy.STATELESS`: No session will be created or used by Spring Security. This is essential for REST APIs and when using stateless authentication mechanisms like JWT.

### Concurrent Session Control

You can limit the number of active sessions a user can have simultaneously. This helps prevent users from sharing their accounts.

To enable concurrent session control, you need to:

1. Add a listener to your `web.xml` or as a `Bean`.
2. Configure session management in your security configuration.

**1. Add `HttpSessionEventPublisher` Bean:**
This listener ensures that the Spring Security session registry is notified when a session is destroyed.

```java
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SessionListenerConfig {
    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }
}
```

**2. Configure `maximumSessions`:**

```java
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class ConcurrentSessionSecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .sessionManagement(session -> session
                .maximumSessions(1) // Allow only one active session per user
                .expiredUrl("/login?expired") // Redirect to this URL if session expires
            );
        return http.build();
    }
}
```

With `maximumSessions(1)`, if a user tries to log in from a second location, the first session will be invalidated.

### Session Fixation Protection

Session fixation is an attack that permits an attacker to hijack a valid user session. Spring Security provides protection against this by default.

When a user authenticates, Spring Security invalidates the existing session, creates a new one, and migrates the session attributes. This is the default behavior (`sessionFixation().migrateSession()`).

You can customize this behavior:

```java
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SessionFixationSecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .sessionManagement(session -> session
                .sessionFixation(fixation -> fixation
                    .newSession() // Creates a new session without migrating attributes
                )
            );
        return http.build();
    }
}
```

Other options include:

* `migrateSession()`: (Default) Creates a new session and migrates attributes.
* `newSession()`: Creates a new session without migrating attributes.
* `none()`: Disables session fixation protection. Not recommended.

This covers the main aspects of session management in Spring Security. Understanding these concepts is crucial for building secure, stateful web applications.

## 7. CSRF Protection and Other Attacks

Spring Security provides out-of-the-box protection against several common web application vulnerabilities.

### CSRF (Cross-Site Request Forgery)

**What is CSRF?**

A CSRF attack tricks a victim into submitting a malicious request. It inherits the identity and privileges of the victim to perform an undesired function on their behalf. For instance, an attacker could trick a logged-in user into clicking a link that transfers money from the user's bank account without their knowledge.

#### How Spring Security Protects Against CSRF

By default, Spring Security enables CSRF protection. It works by requiring a secret, unpredictable token (called a CSRF token) to be included in any state-changing request (e.g., `POST`, `PUT`, `DELETE`).

1. When a user visits a page with a form, the server generates a unique CSRF token and includes it as a hidden field in the form.
2. When the user submits the form, the token is sent back to the server.
3. The server compares the submitted token with the one it has stored for the user's session.
4. If the tokens match, the request is processed. If they don't, the request is rejected with a 403 Forbidden error.

This prevents an attacker from forging a request because they cannot guess the CSRF token.

#### Working with CSRF Protection

If you are using Thymeleaf or Spring MVC's `<form:form>` tag, the CSRF token is automatically added as a hidden input field.

For a standard HTML form, you need to add it manually:

```html
<form th:action="@{/transfer}" method="post">
    <!-- ... other form fields ... -->
    <input type="hidden"
           th:name="${_csrf.parameterName}"
           th:value="${_csrf.token}" />
    <input type="submit" value="Transfer"/>
</form>
```

#### CSRF and AJAX

For AJAX requests (e.g., with `fetch` or jQuery), you need to include the CSRF token in the request headers. A common practice is to get the token from a meta tag in your HTML's `<head>` section.

1. **Add meta tags:**

    ```html
    <meta name="_csrf" th:content="${_csrf.token}"/>
    <meta name="_csrf_header" th:content="${_csrf.headerName}"/>
    ```

2. **Include in AJAX request header:**

    ```javascript
    const token = document.querySelector('meta[name="_csrf"]').getAttribute('content');
    const header = document.querySelector('meta[name="_csrf_header"]').getAttribute('content');

    fetch('/api/resource', {
        method: 'POST',
        headers: {
            [header]: token,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ /* data */ })
    });
    ```

#### Disabling CSRF Protection

CSRF protection is crucial for stateful applications where the browser manages sessions. However, for stateless applications (like APIs that use JWT for authentication), CSRF is not a concern because there is no session/cookie for an attacker to leverage.

You can disable it in your security configuration:

```java
@Configuration
@EnableWebSecurity
public class CsrfDisabledSecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable()); // Disable CSRF
        return http.build();
    }
}
```

### Other Common Attacks and Protections

Spring Security helps protect against other vulnerabilities by managing security headers.

#### Clickjacking Protection

Clickjacking is an attack that tricks a user into clicking something different from what they perceive. Spring Security mitigates this by adding the `X-Frame-Options` header to responses, which controls whether your site can be rendered in an `<frame>`, `<iframe>`, or `<object>`.

By default, it is set to `DENY`, which prevents framing entirely. You can configure it:

```java
@Configuration
@EnableWebSecurity
public class SecurityHeadersConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .headers(headers -> headers
                .frameOptions(frameOptions -> frameOptions
                    .sameOrigin() // Allow framing only from the same origin
                )
            );
        return http.build();
    }
}
```

#### Content Security Policy (CSP)

CSP is a security layer that helps detect and mitigate certain types of attacks, including Cross-Site Scripting (XSS) and data injection. You can configure a CSP header to tell the browser which dynamic resources are allowed to load.

```java
@Configuration
@EnableWebSecurity
public class CspSecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .headers(headers -> headers
                .contentSecurityPolicy(csp -> csp
                    .policyDirectives("script-src 'self'; object-src 'none';")
                )
            );
        return http.build();
    }
}
```

#### HTTP Strict Transport Security (HSTS)

HSTS tells browsers that a site should only be accessed using HTTPS, instead of HTTP. This helps prevent protocol downgrade attacks and cookie hijacking.

```java
@Configuration
@EnableWebSecurity
public class HstsSecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .headers(headers -> headers
                .httpStrictTransportSecurity(hsts -> hsts
                    .includeSubDomains(true)
                    .maxAgeInSeconds(31536000)
                )
            );
        return http.build();
    }
}
```

By understanding and correctly configuring these features, you can significantly improve the security posture of your application.

## 8. JWT (JSON Web Token) Integration

JWT is a compact, URL-safe means of representing claims to be transferred between two parties. It's commonly used for stateless authentication in modern web applications and APIs.

### How JWT Works with Spring Security

1. A user authenticates with their credentials (e.g., username/password).
2. The server verifies the credentials and, if valid, generates a JWT.
3. The server sends the JWT back to the client.
4. The client stores the JWT (e.g., in localStorage or cookies) and includes it in the `Authorization` header of subsequent requests (e.g., `Authorization: Bearer <token>`).
5. A custom Spring Security filter on the server intercepts each request, validates the JWT, and if valid, sets the user's authentication context.

### Steps for JWT Integration

**1. Add JWT Dependency:**
Add a library for creating and parsing JWTs to your `pom.xml`. `jjwt` is a popular choice.

```xml
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-api</artifactId>
    <version>0.11.5</version>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-impl</artifactId>
    <version>0.11.5</version>
    <scope>runtime</scope>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-jackson</artifactId>
    <version>0.11.5</version>
    <scope>runtime</scope>
</dependency>
```

**2. Create a JWT Utility Class:**
This class will handle JWT creation and validation.

```java
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtUtil {

    private String SECRET_KEY = "secret"; // Use a strong, securely stored secret

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, userDetails.getUsername());
    }

    private String createToken(Map<String, Object> claims, String subject) {
        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10)) // 10 hours
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY).compact();
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}
```

**3. Create a JWT Request Filter:**
This filter will execute once per request.

```java
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        final String authorizationHeader = request.getHeader("Authorization");

        String username = null;
        String jwt = null;

        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            jwt = authorizationHeader.substring(7);
            username = jwtUtil.extractUsername(jwt);
        }

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

            if (jwtUtil.validateToken(jwt, userDetails)) {
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                usernamePasswordAuthenticationToken
                        .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            }
        }
        chain.doFilter(request, response);
    }
}
```

**4. Configure Spring Security for JWT:**

```java
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class JwtSecurityConfig {

    @Autowired
    private JwtRequestFilter jwtRequestFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/authenticate").permitAll() // Endpoint to get the token
                .anyRequest().authenticated()
            )
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // Stateless session management
            );
        
        http.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
    
    // ... UserDetailsService and PasswordEncoder beans
}
```

**5. Create an Authentication Endpoint:**
You need an endpoint for users to post their credentials and get a token.

```java
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
class AuthenticationController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtTokenUtil;

    @Autowired
    private UserDetailsService userDetailsService;

    @PostMapping("/authenticate")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) throws Exception {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(), authenticationRequest.getPassword())
            );
        } catch (BadCredentialsException e) {
            throw new Exception("Incorrect username or password", e);
        }

        final UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequest.getUsername());
        final String jwt = jwtTokenUtil.generateToken(userDetails);

        return ResponseEntity.ok(new AuthenticationResponse(jwt));
    }
}

// Helper classes for request and response
class AuthenticationRequest {
    private String username;
    private String password;
    // getters and setters
}

class AuthenticationResponse {
    private final String jwt;
    public AuthenticationResponse(String jwt) { this.jwt = jwt; }
    public String getJwt() { return jwt; }
}
```

This completes the tutorial on Spring Security and JWT integration. You now have the building blocks to secure your Spring Boot applications effectively.
