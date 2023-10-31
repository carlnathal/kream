package com.cos.jwt.service;


import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        System.out.println("로드유저바이유저네임 실행"+username);
        return userRepository.findByUsername(username)
                .map(this::createUserDetails)
                .orElseThrow(()-> new UsernameNotFoundException(username + " -> 데이터베이스에서 찾을 수 없습니다."));

    }



    // 디비에 user 값이 존재한다면 UserDetails 객체로 만들어서 리턴
    private UserDetails createUserDetails(User user){
        System.out.println("왜 안 되" + user.getAuthority());
        System.out.println("크리에이트유저디테일 실행"+user.getAuthority().toString());
        GrantedAuthority grantedAuthority = new SimpleGrantedAuthority(user.getAuthority().toString());
        System.out.println("크리에이트유저디테일 실행");
        System.out.println( user);
        System.out.println("크리에이터유저디테일 진입"+grantedAuthority);

        return new org.springframework.security.core.userdetails.User(
                String.valueOf(user.getId()),
                user.getPassword(),
                Collections.singleton(grantedAuthority)
        );
    }
}
