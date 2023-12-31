//package com.cos.jwt.config;
//
//
//import com.cos.jwt.config.jwt.JwtAuthenticationFilter;
//import com.cos.jwt.config.jwt.JwtAuthorizationFilter;
//import com.cos.jwt.filter.MyFilter1;
//import com.cos.jwt.filter.MyFilter3;
//import com.cos.jwt.repository.UserRepository;
//import lombok.RequiredArgsConstructor;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
//import org.springframework.security.config.http.SessionCreationPolicy;
//import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
//import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;
//import org.springframework.web.filter.CorsFilter;
//
//@Configuration
//@EnableWebSecurity
//@RequiredArgsConstructor
//public class SecurityConfig extends WebSecurityConfigurerAdapter {
//
//
//
//    private final CorsFilter corsFilter;
//    private final UserRepository userRepository;
//
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
////        http.addFilterBefore(new MyFilter3(), SecurityContextHolderAwareRequestFilter.class);
//        http.csrf().disable();
//        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//                .and()
//                .addFilter(corsFilter)
//                .formLogin().disable()
//                .httpBasic().disable()
//                .addFilter(new JwtAuthenticationFilter(authenticationManager())) //AuthenticationManager 를 파라미터로 줘야함
//                .addFilter(new JwtAuthorizationFilter(authenticationManager(), userRepository))
//                .authorizeRequests()
//                .antMatchers("/api/v1/user/**")
//                .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
//                .antMatchers("/api/v1/manager/**")
//                .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
//                .antMatchers("/api/v1/admin/**")
//                .access("hasRole('ROLE_ADMIN')")
//                .anyRequest().permitAll();
//    }
//}
