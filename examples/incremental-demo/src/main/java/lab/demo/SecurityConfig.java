package lab.demo;

/** 未变更文件：安全配置只覆盖 /admin/**，因此 /report/** 没有配置级兜底。 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .antMatchers("/admin/**").hasRole("ADMIN")
            .antMatchers("/login").permitAll();
        return http.build();
    }
}
