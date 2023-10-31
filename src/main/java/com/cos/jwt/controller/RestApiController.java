package com.cos.jwt.controller;


import com.cos.jwt.dto.UserDto;
import com.cos.jwt.dto.UserResponseDto;
import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;
import com.cos.jwt.service.UserService;
import com.cos.jwt.util.SecurityUtil;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;


//@CrossOrigin 인증이 필요없는 경우에 Cors 처리 하는 어노테이션
@RestController
@RequiredArgsConstructor
public class RestApiController {

    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final UserRepository userRepository;
    private final UserService userService;


    @PostMapping("/check")
    public ResponseEntity<Boolean> check(){
        return ResponseEntity.ok(true);
    }

    @GetMapping("home")
    public String home(){


        return "<h1>home</h1>";
    }

    @PostMapping("token")
    public String token(){


        return "<h1>token</h1>";
    }

    @PostMapping("/jwt/check")
    public ResponseEntity<Boolean> check(@RequestBody UserDto userDto){

        System.out.println(userDto.getUsername());
        boolean exists = userService.isUsernameExists(userDto.getUsername());
        return ResponseEntity.ok(exists);
    }

    @PostMapping("/jwt/sign")
    public ResponseEntity<Boolean> sign(@RequestBody UserDto userDto){

        userDto.setPassword(bCryptPasswordEncoder.encode(userDto.getPassword()));
        userDto.setRoles("ROLE_USER");
        boolean success = userService.sign(userDto);

        return  ResponseEntity.ok(success);
    }

    @PostMapping("/jwt/email")
    public ResponseEntity<Boolean> email(@RequestBody UserDto userDto){
        System.out.println(userDto.getEmail());
        boolean exists = userService.isEmailExists(userDto.getEmail());
        return ResponseEntity.ok(exists);
    }


    @PostMapping("/jwt/chocheon")
    public ResponseEntity<Boolean> chocheon(@RequestBody UserDto userDto){
        System.out.println(userDto.getChocheon());
        boolean exists = userService.isChocheonExists(userDto.getChocheon());
        return ResponseEntity.ok(exists);
    }

    @GetMapping("/jwt/me")
    public ResponseEntity<UserResponseDto> findUserInfoById(){
        return ResponseEntity.ok(userService.findUserInfoById(SecurityUtil.getCurrentUserId()));
    }

    @GetMapping("/jwt/{email}")
    public ResponseEntity<UserResponseDto> findUserInfoByEmail(@PathVariable String email){
        return ResponseEntity.ok(userService.findUserInfoByEmail(email));
    }


//    @PostMapping("join")
//    public String join(@RequestBody User user){
//        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
//        user.setRoles("ROLE_USER");
//        userRepository.save(user);
//        return "회원가입완료";
//    }



    //유저권한 매니저 어드민 접근 가능
    @GetMapping("/api/v1/user")
    public String user(){
        return "user";
    }
    //매니저 어드민만 가능
    @GetMapping("/api/v1/manager")
    public String manager(){
        return "manager";
    }
    //어드민만 가능
    @GetMapping("/api/v1/admin")
    public String admin(){
        return "admin";
    }
}
