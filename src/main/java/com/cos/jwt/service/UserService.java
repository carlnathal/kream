package com.cos.jwt.service;


import com.cos.jwt.dto.UserDto;
import com.cos.jwt.dto.UserResponseDto;
import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserService {


    @Autowired
    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public boolean isUsernameExists(String username){
        return userRepository.findByUsername(username)
                .map((user -> user != null))
                .orElse(false);

    }

    public boolean isEmailExists(String email){
        return userRepository.findByEmail(email)
                .map((user -> user != null))
                .orElse(false);

    }

    public boolean isChocheonExists(String chocheon){
        User user = userRepository.findByChocheon(chocheon);
        return user != null;
    }

    public boolean sign(UserDto userDto){

        User user = User.builder()
                .username(userDto.getUsername())
                .password(userDto.getPassword())
                .irum(userDto.getIrum() )
                .email(userDto.getEmail())
                .hp(userDto.getHp())
                .addr(userDto.getAddr())
                .chocheon(userDto.getChocheon())
                .foot(userDto.getFoot())
                .accepted(userDto.getAccepted())
                .my(userDto.getMy())
                .roles("ROLE_USER")
                .build();
        User user2 = userRepository.save(user);
        System.out.println(user2);

        return true;
    }

    public UserResponseDto findUserInfoById(Long userId){
        return userRepository.findById(userId)
                .map(UserResponseDto::of)
                .orElseThrow(()-> new RuntimeException("로그인 유저 정보가 없습니다."));
    }

    public UserResponseDto findUserInfoByEmail(String email){
        return userRepository.findByEmail(email)
                .map(UserResponseDto::of)
                .orElseThrow(()-> new RuntimeException("유저 정보가 없습니다"));

    }
}
