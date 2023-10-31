package com.cos.jwt.jwtsecurity;


import com.cos.jwt.dto.TokenDto;
import com.cos.jwt.dto.UserDto;
import com.cos.jwt.model.RefreshToken;
import com.cos.jwt.repository.RefreshTokenRepository;
import com.cos.jwt.repository.UserRepository;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Component
public class TokenProvider {


    private final UserRepository userRepository;

    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    private final RefreshTokenRepository refreshTokenRepository;

    private static final String AUTHORITIES_KEY = "auth";
    private static final String BEARER_TYPE = "Bearer";
    private static final long ACCESS_TOKEN_EXPIRE_TIME = 1000 * 60 * 30;

    private static final long LOGOUT_ACCESS_TOKEN_EXPIRE_TIME = 0;
    private static final long REFRESH_TOKEN_EXPIRE_TIME = 1000 * 60 * 60 * 24 * 7;

    private final Key key;

    public TokenProvider(@Value("${jwt.secret}") String secretKey, UserRepository userRepository, AuthenticationManagerBuilder authenticationManagerBuilder, RefreshTokenRepository refreshTokenRepository){
        this.userRepository = userRepository;
        this.authenticationManagerBuilder = authenticationManagerBuilder;
        this.refreshTokenRepository = refreshTokenRepository;
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    public TokenDto generateTokenDto(Authentication authentication){
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        long now = new Date().getTime();




        //엑세스 토큰 생성
        Date accessTokenExpiresIn = new Date(now + ACCESS_TOKEN_EXPIRE_TIME);
        String accessToken = Jwts.builder()
                .setSubject(authentication.getName()) // payload "sub": "name"
                .claim(AUTHORITIES_KEY, authorities)     // payload "auth": "ROLE_USER"
                .setExpiration(accessTokenExpiresIn)      // payload "exp": 1516239022 (예시)
                .signWith(key, SignatureAlgorithm.HS512)    // header "alg": "HS512"
                .compact();

        String userName = authentication.getName(); // getName은 user의 고유 id 프라이머리키를 리턴하는 거 같은디...
        Long userId = Long.valueOf(userName);
        UserDto userDto = userRepository.findById(userId).map(UserDto::of).orElseThrow(()-> new RuntimeException("회원 정보가 없습니다."));

        //리프레쉬 토큰이랑 액세스 토큰을 어떻게 할 것인가...
        // 액세스 토큰이 탈취된다면?
        // 리프레쉬 토큰이 탈취된다면?
        // 둘 다 탈취된다면?
        // 액세스 토큰은 유효기간이 짧다
        // 리프레쉬 토큰을 검증할 때 디비를 같이 묶여있던 액세스 토큰이 만료되었음을 확인을 해야 새로운 액세스 토큰과 함께 기존 리프뤠시 토큰을
        // 만료시키고 새로운 액세스 토큰과 묶인 리프레쉬 토큰을 또 디비에 저장시키고 발급한다. 그럼 리프뤠시 토큰만 탈취된 경우를 막을 수 있다.
        // http only 로 쿠키 설정
        // 리프레시 토큰에도 유저 정보를 넣고 유저 정보를 키로 토큰을 벨류로 해서
        // 재발급 시에 리프레쉬토큰을 까보고 유저 정보를 얻고 디비에서 조회를 해보고 디비에서 꺼낸 토큰과 내 리프레쉬토큰이 같은지 비교하고
        // 액세스 리프레쉬 둘 다 재발급하고 디비에 리프뤠시 토큰도 다시 등록
        // 근데 디비랑 액세스 토큰 재발급시 유저가 내놓은 리프레쉬토큰이 일치하지 않으면 디비에 정보 삭제 후 다시 로그인 시킨다.
        // 다시 로그인 시키면 유저 정보 하나의 키에 저장된 벨류 값이 또 바뀌닌깐 리프레쉬 토큰에 대한 잘못된 접근을 조금이나마 막을 수 있다.

        UUID refreshTokenUUID = UUID.randomUUID();

        String refreshToken = Jwts.builder()
                .setSubject(authentication.getName()) // payload "sub": "name"
                .claim("ID", refreshTokenUUID.toString().replace("-",""))
                .setExpiration(new Date(now + REFRESH_TOKEN_EXPIRE_TIME))
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();

        return TokenDto.builder()
                .grantType(BEARER_TYPE)
                .accessToken(accessToken)
                .accessTokenExpiresIn(accessTokenExpiresIn.getTime())
                .refreshToken(refreshToken)
                .build();


    }

    public TokenDto logoutGenerateTokenDto(Authentication authentication){
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        long now = new Date().getTime();




        //엑세스 토큰 생성
        Date accessTokenExpiresIn = new Date(now + LOGOUT_ACCESS_TOKEN_EXPIRE_TIME);
        String accessToken = Jwts.builder()
                .setSubject(authentication.getName()) // payload "sub": "name"
                .claim(AUTHORITIES_KEY, authorities)     // payload "auth": "ROLE_USER"
                .setExpiration(accessTokenExpiresIn)      // payload "exp": 1516239022 (예시)
                .signWith(key, SignatureAlgorithm.HS512)    // header "alg": "HS512"
                .compact();

        String userName = authentication.getName(); // getName은 user의 고유 id 프라이머리키를 리턴하는 거 같은디...
        Long userId = Long.valueOf(userName);
        UserDto userDto = userRepository.findById(userId).map(UserDto::of).orElseThrow(()-> new RuntimeException("회원 정보가 없습니다."));

        //리프레쉬 토큰이랑 액세스 토큰을 어떻게 할 것인가...
        // 액세스 토큰이 탈취된다면?
        // 리프레쉬 토큰이 탈취된다면?
        // 둘 다 탈취된다면?
        // 액세스 토큰은 유효기간이 짧다
        // 리프레쉬 토큰을 검증할 때 디비를 같이 묶여있던 액세스 토큰이 만료되었음을 확인을 해야 새로운 액세스 토큰과 함께 기존 리프뤠시 토큰을
        // 만료시키고 새로운 액세스 토큰과 묶인 리프레쉬 토큰을 또 디비에 저장시키고 발급한다. 그럼 리프뤠시 토큰만 탈취된 경우를 막을 수 있다.
        // http only 로 쿠키 설정
        // 리프레시 토큰에도 유저 정보를 넣고 유저 정보를 키로 토큰을 벨류로 해서
        // 재발급 시에 리프레쉬토큰을 까보고 유저 정보를 얻고 디비에서 조회를 해보고 디비에서 꺼낸 토큰과 내 리프레쉬토큰이 같은지 비교하고
        // 액세스 리프레쉬 둘 다 재발급하고 디비에 리프뤠시 토큰도 다시 등록
        // 근데 디비랑 액세스 토큰 재발급시 유저가 내놓은 리프레쉬토큰이 일치하지 않으면 디비에 정보 삭제 후 다시 로그인 시킨다.
        // 다시 로그인 시키면 유저 정보 하나의 키에 저장된 벨류 값이 또 바뀌닌깐 리프레쉬 토큰에 대한 잘못된 접근을 조금이나마 막을 수 있다.

        UUID refreshTokenUUID = UUID.randomUUID();

        String refreshToken = Jwts.builder()
                .setSubject(authentication.getName()) // payload "sub": "name"
                .claim("ID", refreshTokenUUID.toString().replace("-",""))
                .setExpiration(new Date(now + 0))
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();

        return TokenDto.builder()
                .grantType(BEARER_TYPE)
                .accessToken(accessToken)
                .accessTokenExpiresIn(accessTokenExpiresIn.getTime())
                .refreshToken(refreshToken)
                .build();


    }

    public Authentication getAuthentication(String accessToken){



        Claims claims = parseClaims(accessToken);

        if (claims.get(AUTHORITIES_KEY)==null){
            throw new RuntimeException("권한 정보가 없는 토큰입니다.");
        }


        //클레임에서 권한 정보 가져오기
        Collection<? extends GrantedAuthority> authorities = Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());




        //UserDetails 객체를 만들어서 Authentication 리턴
        UserDetails principal = new User(claims.getSubject(), "", authorities);

        Authentication authentication = new UsernamePasswordAuthenticationToken(principal, "", authorities);

         return authentication;
    }

    //리프레쉬 토큰을 까서 id가져오는 걸 해보자
    public Authentication getAuthenticationWithRefreshToken(String requestRefreshToken){

        String userIdStr = getUserId(requestRefreshToken);
        System.out.println(userIdStr);
        RefreshToken refreshToken;

        Long userId = Long.valueOf(userIdStr);

        // 리프레쉬 토큰에서 아이디 꺼내서 디비에서 리프뤠시 토큰 다시 조회해서 둘 값 비교
                    refreshToken = refreshTokenRepository.findById(userIdStr)
                    .orElseThrow(()-> new RuntimeException("로그아웃된 사용자입니다."));

        if(!refreshToken.getValue().equals(requestRefreshToken)){
            throw new RuntimeException("토큰의 유저 정보가 일치하지 않습니다.");
        }


        UserDto userDto = userRepository.findById(userId).map(UserDto::of).orElseThrow(()-> new RuntimeException("회원정보가 없습니다."));


        Collection<? extends GrantedAuthority> authorities = Arrays.stream(userDto.getRoles().toString().split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        //UserDetails 객체를 만들어서 Authentication 리턴
        UserDetails principal = new User(userIdStr, "", authorities);

        Authentication authentication = new UsernamePasswordAuthenticationToken(principal, "", authorities);

        return authentication;

    }

    public String getUserId(String refreshToken){
        Claims claims = parseClaims(refreshToken);
        return claims.getSubject();
    }



    public boolean validateToken(String token){
        try{
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (io.jsonwebtoken.security.SignatureException | MalformedJwtException e){
            log.info("잘못된 JWT 서명입니다.");

        } catch (ExpiredJwtException e){
            log.info("만료된 JWT 토큰입니다.");
        } catch (UnsupportedJwtException e){
            log.info("지원되지 않는 JWT 토큰입니다");
        } catch (IllegalArgumentException e){
            log.info("JWT 토큰이 잘못되었습니다.");
        }
        return false;
    }

    private Claims parseClaims(String accessToken){
        try {
            return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(accessToken).getBody();
        } catch (ExpiredJwtException e){
            return e.getClaims();
        }
    }
}
