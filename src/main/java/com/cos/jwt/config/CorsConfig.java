package com.cos.jwt.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsConfig {


    @Bean
    public CorsConfigurationSource corsConfigurationSource(){
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true); // 내 서버가 응답할 때 제이슨을 자바스크립트에서 처리할 수 있게 할지 설정
        config.addAllowedOriginPattern("*"); // 모든 아이피 응답 허용
        config.addAllowedHeader("*"); // 모든 헤더에 응답 허용
        config.addAllowedMethod("*"); // 포스트 겟 풋 딜리트 허용
        source.registerCorsConfiguration("/**", config);
        return source;

    }
}
