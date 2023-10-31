package com.cos.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;


//스프링 시큐리티에서 UsernamePasswordAuthenticationFilter 가 있음.
// /login 요청해서 username과 password 전송하면 post로
//

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;


    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter : 로그인 시도중");

        //1. 유저네임과 패스워드 받아서

        try {
//            BufferedReader br = request.getReader();
//            String input = null;
//            while((input=br.readLine()) != null){
//                System.out.println(input);
//            }
//            System.out.println(request.getInputStream());
            System.out.println("==================================");
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println(user);

            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());


            //PrincipalDetailsService의 loadUserByUsername() 함수가 실행됨 그 후 정상이면 authentication이 리턴 됨
            //DB에 있는 username과 password가 일치한다./
            //실제로 로그인을 정상적으로 해서 만든 어썬티케이션 객체
            Authentication authentication = authenticationManager.authenticate(authenticationToken);


            // authentication 에 로그인 정보가 담김

            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("로그인 완료됨" + principalDetails.getUser().getUsername()); //값이 있다는 건 로그인이 되었다는 뜻
            //authentication 객체가 세션영역에 저장을 해야하고 그 방법이 리턴 해주면 됨
            //리턴의 이유는 권한 관리를 시큐리티가 대신 해주기 때문에 편하려고 하는 거
            //굳이 JWT토큰을 사용하면서 세션을 만들 이유가 없음 근데 단지 권한 처리 때문에 세션에 넣어줍니다.


            //  리턴될 때 authentication 이 세션 영역에 저장이 됨 => 로그인이 되었음
            return authentication;

        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        //2.정상인지 로그인 시도를 해봄 authenticationManager로 로그인 시도를 하면 PrincipalDetailsService가 호출 loadUserByUsername() 함수가 실행됨
        //3. PrincipalDetails가 리턴되고 걔를 세션에 담고(권한 관리를 위해) 권한 관리 안할 거면 세션에 담지 않아도 됨
        //4. JWT토큰을 만들어서 응답해주면 됨


    }


    //attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행 됨
    //JWT토큰을 만들어서 리퀘스트 요청한 사용자에게 JWT토큰을 리스폰스 해주면 됨
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication 실행됨 : 인증이 완료되었다는 뜻");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        // RSA방식은 아니고 Hash암호방식
        String jwtToken = JWT.create()
                        .withSubject("cos토큰")
                                .withExpiresAt(new Date(System.currentTimeMillis()+JwtProperties.EXPIRATION_TIME))
                                        .withClaim("id",principalDetails.getUser().getId())
                                                .withClaim("username",principalDetails.getUser().getUsername())
                                                        .sign(Algorithm.HMAC512(JwtProperties.SECRET));

        response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX+jwtToken);


    }
}
