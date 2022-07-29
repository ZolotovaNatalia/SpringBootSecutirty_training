package com.example.demo.security;

import com.example.demo.jwt.JwtConfig;
import com.example.demo.jwt.JwtSecretKey;
import com.example.demo.jwt.JwtUsernamePasswordAuthenticationFilter;
import com.example.demo.jwt.TokenVerifier;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.crypto.SecretKey;

import static com.example.demo.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtConfig jwtConfig;

    @Autowired
    private SecretKey secretKey;

    @Bean
    public SecurityFilterChain filterChain(@Qualifier("userDetailsService") UserDetailsService userDetailsService, HttpSecurity http) throws Exception {
        AuthenticationManager authenticationManager = getAuthenticationManager(userDetailsService);

        http
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeHttpRequests((authz) -> authz
                        .antMatchers("index", "/css/*", "/").permitAll()
                        .antMatchers("/api/**").hasRole(STUDENT.name())
//                        .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                        .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                        .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                        .antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())
                        .anyRequest()
                        .authenticated())
                .addFilterBefore(new JwtUsernamePasswordAuthenticationFilter(authenticationManager, jwtConfig, secretKey), JwtUsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(new TokenVerifier(jwtConfig, secretKey), JwtUsernamePasswordAuthenticationFilter.class);

//                .defaultSuccessUrl("/courses", true)
//                .and()
//                .rememberMe()
//                .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
//                .key("somethingverysecured")
//                .and()
//                .logout()
//                .logoutUrl("/logout")
//                .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
//                .clearAuthentication(true)
//                .invalidateHttpSession(true)
//                .deleteCookies("JSESSIONID", "remember-me")
//                .logoutSuccessUrl("/login");


        return http.build();
    }

    private AuthenticationManager getAuthenticationManager(UserDetailsService userDetailsService) {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(userDetailsService);
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder);
        AuthenticationManager authenticationManager = new ProviderManager(daoAuthenticationProvider);
        return authenticationManager;
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails nata = User.builder()
                .username("nata")
                .password(passwordEncoder.encode("nata"))
//                .roles(STUDENT.name())
                .authorities(STUDENT.getGrantedAuthority())
                .build();

        UserDetails peter = User.builder()
                .username("peter")
                .password(passwordEncoder.encode("123"))
//                .roles(ADMIN.name())
                .authorities(ADMIN.getGrantedAuthority())
                .build();

        UserDetails puppy = User.builder()
                .username("puppy")
                .password(passwordEncoder.encode("puppy"))
//                .roles(ADMINTRAINEE.name())
                .authorities(ADMINTRAINEE.getGrantedAuthority())
                .build();

        return new InMemoryUserDetailsManager(nata, peter, puppy);
    }


}
