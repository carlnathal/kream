package com.cos.jwt.config;


import com.cos.jwt.filter.MyFilter1;
import com.cos.jwt.filter.MyFilter2;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;



//이 필터들은 시큐리티가 다 동작된 다음에야 실행이 됨
@Configuration
public class FilterConfig {

    @Bean
    public FilterRegistrationBean<MyFilter1> filter1 (){
        FilterRegistrationBean<MyFilter1> been = new FilterRegistrationBean<>(new MyFilter1());
        been.addUrlPatterns("/*");
        been.setOrder(0); //낮은 번호가 필터 중에서 가장 먼저 실행됨

        return been;
    }

    @Bean
    public FilterRegistrationBean<MyFilter2> filter2 (){
        FilterRegistrationBean<MyFilter2> been = new FilterRegistrationBean<>(new MyFilter2());
        been.addUrlPatterns("/*");
        been.setOrder(1); //낮은 번호가 필터 중에서 가장 먼저 실행됨

        return been;
    }
}
