# CustomJwtSendingProvider.java
```
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

@Component
public class CustomJwtSendingProvider implements AuthenticationProvider {

    private final WebClient webClient;

    public CustomJwtSendingProvider(WebClient webClient) {
        this.webClient = webClient;
    }

    @Override
    public Authentication authenticate(Authentication authentication) {
        String jwtToken = (String) authentication.getPrincipal();

        // Add your custom logic to validate the JWT token (if needed)

        // Send the JWT as a custom header to the external service
        ResponseEntity<Void> response = webClient.get()
            .uri("YOUR_EXTERNAL_SERVICE_URL")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwtToken)
            .retrieve()
            .toBodilessEntity()
            .block();

        if (response.getStatusCode().is2xxSuccessful()) {
            // Authentication successful
            return authentication;
        } else {
            throw new BadCredentialsException("Failed to authenticate");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JwtAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
```

# SecurityConfig.java
```
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.annotation.web.reactive.WebFluxConfigurer;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig implements WebFluxConfigurer {

    @Bean
    public WebClient webClient() {
        return WebClient.builder().build();
    }

    @Bean
    public AuthenticationProvider customJwtSendingProvider(WebClient webClient) {
        return new CustomJwtSendingProvider(webClient);
    }

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
            .authorizeExchange()
            .anyExchange().authenticated()
            .and()
            .httpBasic().disable()
            .formLogin().disable()
            .csrf().disable()
            .build();
    }
}


```
