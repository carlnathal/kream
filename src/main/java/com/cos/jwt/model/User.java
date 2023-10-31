package com.cos.jwt.model;


import lombok.*;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Entity
@Getter
@ToString
@Builder
public class User {


    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    @Column(unique = true, nullable = false, length = 16)
    private String username;
    private String password;
    private String irum;
    private String hp;
    private String addr;
    private String chocheon;
    private String foot;
    private String accepted;
    private String my;
    private String email;
    private String roles;

    @Enumerated(EnumType.STRING)
    private Authority authority;


    public List<String> getRoleList(){
        if(this.roles.length() > 0){
            return Arrays.asList(this.roles.split(","));
        }
        return new ArrayList<>();
    }



}

