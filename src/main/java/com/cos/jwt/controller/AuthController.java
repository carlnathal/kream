package com.cos.jwt.controller;


import com.cos.jwt.dto.TokenDto;
import com.cos.jwt.dto.TokenRequestDto;
import com.cos.jwt.dto.UserDto;
import com.cos.jwt.dto.UserRequestDto;
import com.cos.jwt.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {


    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<TokenDto> login(@RequestBody UserRequestDto userRequestDto, HttpServletResponse response){




        TokenDto tokenDto = authService.login(userRequestDto);

//        Cookie accesstokenCookie = new Cookie("ACCESSTOKEN", tokenDto.getAccessToken());
//
//        accesstokenCookie.setMaxAge(60 * 30);
//        accesstokenCookie.setHttpOnly(true);
//        accesstokenCookie.setPath("/");
//
//        response.addCookie(accesstokenCookie);

        Cookie refreshtokenCookie = new Cookie("REFRESHTOKEN", tokenDto.getRefreshToken());


        refreshtokenCookie.setMaxAge(2 * 7 * 24 * 60 * 60);

//        refreshtokenCookie.setSecure(true); https통신에서만 가능하게 하는 것
        refreshtokenCookie.setHttpOnly(true); // 자바스크립트로 쿠키 접근 못하게 막는 것
        refreshtokenCookie.setPath("/");
        refreshtokenCookie.setDomain("carlnathal.shop");

        response.addCookie(refreshtokenCookie);


        TokenDto responseTokenDto = TokenDto.builder()
                .grantType(tokenDto.getGrantType())
                .accessToken(tokenDto.getAccessToken())
                .accessTokenExpiresIn(tokenDto.getAccessTokenExpiresIn())
                .build();

        return ResponseEntity.ok(responseTokenDto);
    }

    @PostMapping("/reissue")
    public ResponseEntity<TokenDto> reissue(@CookieValue(name = "REFRESHTOKEN", required = true) String requestRefreshToken, @RequestHeader(value="Authorization",required = false) String accessToken, HttpServletResponse response){

        String noBearerAccessToken = null;
        TokenDto responseTokenDto;

        if (accessToken != null && accessToken.startsWith("Bearer ")) {

            noBearerAccessToken = accessToken.substring(7); // "Bearer " 다음의 문자열을 추출합니다.


            TokenDto tokenDto = authService.reissue(requestRefreshToken, noBearerAccessToken);
            Cookie cookie = new Cookie("REFRESHTOKEN", tokenDto.getRefreshToken());

            cookie.setMaxAge(7 * 24 * 60 * 60);

            cookie.setHttpOnly(true);
            cookie.setPath("/");
            cookie.setDomain("carlnathal.shop");

            response.addCookie(cookie);

            responseTokenDto = TokenDto.builder()
                    .grantType(tokenDto.getGrantType())
                    .accessToken(tokenDto.getAccessToken())
                    .accessTokenExpiresIn(tokenDto.getAccessTokenExpiresIn())
                    .build();
        } else {
            TokenDto tokenDto = authService.reissue(requestRefreshToken, noBearerAccessToken);
            Cookie cookie = new Cookie("REFRESHTOKEN", tokenDto.getRefreshToken());

            cookie.setMaxAge(7 * 24 * 60 * 60);

            cookie.setHttpOnly(true);
            cookie.setPath("/");
            cookie.setDomain("carlnathal.shop");

            response.addCookie(cookie);

            responseTokenDto = TokenDto.builder()
                    .grantType(tokenDto.getGrantType())
                    .accessToken(tokenDto.getAccessToken())
                    .accessTokenExpiresIn(tokenDto.getAccessTokenExpiresIn())
                    .build();
        }

        return ResponseEntity.ok(responseTokenDto);
    }

    @PostMapping("/logout")
    public ResponseEntity<TokenDto> logout(@CookieValue(name = "REFRESHTOKEN", required = true) String requestRefreshToken, @RequestHeader(value="Authorization",required = false) String accessToken, HttpServletResponse response) {

        String noBearerAccessToken = null;
        TokenDto responseTokenDto;

        if (accessToken != null && accessToken.startsWith("Bearer ")) {

            noBearerAccessToken = accessToken.substring(7); // "Bearer " 다음의 문자열을 추출합니다.


            TokenDto tokenDto = authService.reissue(requestRefreshToken, noBearerAccessToken);
            Cookie cookie = new Cookie("REFRESHTOKEN", tokenDto.getRefreshToken());

            cookie.setMaxAge(0);

            cookie.setHttpOnly(true);
            cookie.setPath("/");
            cookie.setDomain("carlnathal.shop");

            response.addCookie(cookie);

            responseTokenDto = TokenDto.builder()
                    .grantType(tokenDto.getGrantType())
                    .accessToken(tokenDto.getAccessToken())
                    .accessTokenExpiresIn(tokenDto.getAccessTokenExpiresIn())
                    .build();
        } else {
            TokenDto tokenDto = authService.reissue(requestRefreshToken, noBearerAccessToken);
            Cookie cookie = new Cookie("REFRESHTOKEN", tokenDto.getRefreshToken());

            cookie.setMaxAge(0);

            cookie.setHttpOnly(true);
            cookie.setPath("/");
            cookie.setDomain("carlnathal.shop");

            response.addCookie(cookie);

            responseTokenDto = TokenDto.builder()
                    .grantType(tokenDto.getGrantType())
                    .accessToken(tokenDto.getAccessToken())
                    .accessTokenExpiresIn(tokenDto.getAccessTokenExpiresIn())
                    .build();
        }

        return ResponseEntity.ok(responseTokenDto);

    }

    @GetMapping("/getUserNameEmailHp")
    public ResponseEntity<?> getUserNameEmailHp(@RequestHeader(value="Authorization",required = false) String accessToken){
        // 액세스 토큰을 까서 유저정보 얻어  그것을 토대로 데이터 베이스 조회 조회해서 이름 이메일 Hp만 보내줘
        String noBearerAccessToken = null;
        UserDto userDto;


        if (accessToken != null && accessToken.startsWith("Bearer ")) {
            noBearerAccessToken = accessToken.substring(7); // "Bearer " 다음의 문자열을 추출합니다.

            userDto = authService.getUserDto(noBearerAccessToken);

            return ResponseEntity.ok(userDto);

        } else {

            return ResponseEntity.badRequest().body("잘못된 요청입니다.");
        }


    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<String> handleMissingParameterException(MissingServletRequestParameterException ex) {
        // 필수 매개변수가 누락된 경우에 대한 처리를 여기에 작성
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("RefreshToken이 없습니다.");
    }

}
