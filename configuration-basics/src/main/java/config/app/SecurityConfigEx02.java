package config.app;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfigEx02 {
	// FilterChain에서 제외
	@Bean
	public WebSecurityCustomizer webSecurityCustomizer() {
	    return new WebSecurityCustomizer() {
	        @Override
	        public void customize(WebSecurity web) {
	            web
	                .ignoring()
	                .requestMatchers(new AntPathRequestMatcher("/assets/**"));
	        }
	    };
	}
	
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Throwable {
		return http.build();
	}
	
}

