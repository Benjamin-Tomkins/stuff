```
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

public class CustomAuthFilter implements ServerSecurityContextRepository {

    private final WebClient webClient;
    private final ServerSecurityContextRepository delegate = new WebSessionServerSecurityContextRepository();
    private final ServerWebExchangeMatcher requiresAuthentication = ServerWebExchangeMatchers.anyExchange();

    public CustomAuthFilter(WebClient.Builder webClientBuilder) {
        this.webClient = webClientBuilder.build();
    }

    @Override
    public Mono<Void> save(ServerWebExchange exchange, SecurityContext context) {
        return delegate.save(exchange, context);
    }

    @Override
    public Mono<SecurityContext> load(ServerWebExchange exchange) {
        return requiresAuthentication.matches(exchange)
                .filter(ServerWebExchangeMatcher.MatchResult::isMatch)
                .flatMap(matchResult -> delegate.load(exchange))
                .switchIfEmpty(Mono.defer(() -> checkAuth(exchange)));
    }

    private Mono<SecurityContext> checkAuth(ServerWebExchange exchange) {
        String token = exchange.getRequest().getHeaders().getFirst("X-HSBC-E2E-Trust-Token");
        if (token != null) {
            return webClient.get()
                    .uri("http://auth-check-service/check?token=" + token)
                    .retrieve()
                    .onStatus(HttpStatus::is4xxClientError, clientResponse -> Mono.error(new HttpClientErrorException(clientResponse.statusCode())))
                    .bodyToMono(Void.class)
                    .flatMap(response -> delegate.load(exchange))
                    .doOnError(throwable -> SecurityContextHolder.clearContext());
        }
        return delegate.load(exchange);
    }
}
```

```
http
    .securityContextRepository(new CustomAuthFilter(webClientBuilder))
    ...
```
