package com.cos.jwt.dto;

import com.cos.jwt.model.User;
import lombok.*;

@Getter
@Setter
@ToString
@NoArgsConstructor
@AllArgsConstructor

public class UserDto {

    private long id;
    private String username;
    private String password;
    private String irum;
    private String email;
    private String hp;
    private String addr;
    private String chocheon;
    private String foot;
    private String accepted;
    private String my;
    private String roles;

    public UserDto(long id, String username, String password, String irum, String roles) {
        this.id = id;
        this.username = username;
        this.password = password;
        this.irum = irum;
        this.roles = roles;
    }

    public UserDto(String username, String userEmail, String userHp){
        this.username = username;
        this.email = userEmail;
        this.hp = userHp;
    }

    public static UserDto of(User user){
        return new UserDto(user.getId(), user.getUsername(), user.getPassword(), user.getIrum(), user.getRoles());
    }

    public static UserDto of2(User user){
        return new UserDto(user.getUsername(),user.getEmail(),user.getHp());
    }


}
