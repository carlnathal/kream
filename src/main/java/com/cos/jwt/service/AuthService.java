package com.cos.jwt.service;


import com.cos.jwt.dto.TokenDto;
import com.cos.jwt.dto.TokenRequestDto;
import com.cos.jwt.dto.UserDto;
import com.cos.jwt.dto.UserRequestDto;
import com.cos.jwt.jwtsecurity.TokenProvider;
import com.cos.jwt.model.RefreshToken;
import com.cos.jwt.repository.RefreshTokenRepository;
import com.cos.jwt.repository.UserRepository;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenProvider tokenProvider;
    private final RefreshTokenRepository refreshTokenRepository;

    @Transactional
    public TokenDto login(UserRequestDto userRequestDto){
        // 1. Login ID/PW 를 기반으로 AuthenticationToken 생성
        UsernamePasswordAuthenticationToken authenticationToken = userRequestDto.toAuthentication();
        // 2. 실제로 검증 (사용자 비밀번호 체크)이 이루어지는 부분
        // authenticate 메서드가 실행이 될 때 CustomUserDetailsService 에서 만들었던 loadUserByUsername 메서드가 실행됨
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        System.out.println("어썬티케이션 생성" + authentication);
        // 3. 인증 정보를 기반으로 JWT 토큰 생성
        TokenDto tokenDto = tokenProvider.generateTokenDto(authentication);
        // 4. RefreshToken 저장
        RefreshToken refreshToken = RefreshToken.builder()
                .key(authentication.getName())
                .value(tokenDto.getRefreshToken())
                .build();

        refreshTokenRepository.save(refreshToken);

        // 5. 토큰 발급
        return tokenDto;


    }

    @Transactional
    public TokenDto logout(String requestRefreshToken, String noBearerAccessToken){
        if(!tokenProvider.validateToken(requestRefreshToken)){
            throw new RuntimeException("Refresh Token 이 유효하지 않습니다");
        }


        RefreshToken refreshToken;
        Authentication authentication;

        //액세스 토큰이 존재할 경우에는 액세스 토큰에서 유저 아이디 가져오고
        if(noBearerAccessToken != null){

            // 2. Access Token 에서 User ID 가져오기
            authentication = tokenProvider.getAuthentication(noBearerAccessToken);


            // 3. 저장소에서 User ID 를 기반으로 Refresh Token 값 가져옴
            refreshToken = refreshTokenRepository.findByKey(authentication.getName())
                    .orElseThrow(()-> new RuntimeException("로그아웃된 사용자입니다."));

            //액세스 토큰이 없을 때는 리프레쉬 토큰을 까서 유저 아이디 가져오는 로직
        } else {

            authentication = tokenProvider.getAuthenticationWithRefreshToken(requestRefreshToken);
        }

        // 5. 새로운 토큰 생성
        System.out.println("어썬티케이션 생성");
        TokenDto tokenDto = tokenProvider.logoutGenerateTokenDto(authentication);
        System.out.println("새로운 토큰 생성");




        // 6. 저장소 정보 업데이트
        RefreshToken newRefreshToken = new RefreshToken(authentication.getName(), tokenDto.getRefreshToken());
        refreshTokenRepository.save(newRefreshToken);
        System.out.println("토큰 저장");

        // 토큰 발급
        return tokenDto;
    }

    @Transactional
    public TokenDto reissue(String requestRefreshToken, String noBearerAccessToken){

        System.out.println("리프레쉬 시작");
        // 1. 리프레쉬 토큰 검증
        if(!tokenProvider.validateToken(requestRefreshToken)){
            throw new RuntimeException("Refresh Token 이 유효하지 않습니다");
        }

        RefreshToken refreshToken;
        Authentication authentication;

            // 해야될 게 리프레쉬 토큰을 까서 유저 아이디 가져오고
        // 디비에서 검색해서 리프레쉬토큰 값 가져오고
        // 유저가 보낸 거랑 일치하는지 비교하고
        // 일치 하면 다시 생성

        //액세스 토큰이 존재할 경우에는 액세스 토큰에서 유저 아이디 가져오고
        if(noBearerAccessToken != null){

            // 2. Access Token 에서 User ID 가져오기
            authentication = tokenProvider.getAuthentication(noBearerAccessToken);


            // 3. 저장소에서 User ID 를 기반으로 Refresh Token 값 가져옴
            refreshToken = refreshTokenRepository.findByKey(authentication.getName())
                    .orElseThrow(()-> new RuntimeException("로그아웃된 사용자입니다."));

            //액세스 토큰이 없을 때는 리프레쉬 토큰을 까서 유저 아이디 가져오는 로직
        } else {


            authentication = tokenProvider.getAuthenticationWithRefreshToken(requestRefreshToken);
//            refreshToken = refreshTokenRepository.findByValue(requestRefreshToken)
//                    .orElseThrow(()-> new RuntimeException("로그아웃된 사용자입니다."));


        }


        // 4. Refresh Token 일치하는지 검사는 토큰 프로바이더 쪽에서 해결
//        if(!refreshToken.getValue().equals(requestRefreshToken)){
//            throw new RuntimeException("토큰의 유저 정보가 일치하지 않습니다.");
//        }
        
        // 5. 새로운 토큰 생성
        System.out.println("어썬티케이션 생성");
        TokenDto tokenDto = tokenProvider.generateTokenDto(authentication);
        System.out.println("새로운 토큰 생성");




        // 6. 저장소 정보 업데이트
        RefreshToken newRefreshToken = new RefreshToken(authentication.getName(), tokenDto.getRefreshToken());
        refreshTokenRepository.save(newRefreshToken);
        System.out.println("토큰 저장");

        // 토큰 발급
        return tokenDto;
        
    }

    @Transactional
    public UserDto getUserDto(String noBeareerAccessToken){

        String userIdStr = tokenProvider.getUserId(noBeareerAccessToken);

        Long userId = Long.valueOf(userIdStr);

        UserDto userDto = userRepository.findById(userId).map(UserDto::of2).orElseThrow(()-> new RuntimeException("회원정보가 없습니다."));

        System.out.println(userDto.getHp() + userDto.getEmail());

        UserDto userDto1 = new UserDto(userDto.getUsername(), userDto.getEmail(), userDto.getHp());

        return userDto1;

    }

}
