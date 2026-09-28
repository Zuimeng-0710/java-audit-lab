package lab.security;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/public/**", "/health").permitAll()
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/ops/**").hasAnyRole("ADMIN", "OPS")
                .anyRequest().authenticated();
        return http.build();
    }
}
