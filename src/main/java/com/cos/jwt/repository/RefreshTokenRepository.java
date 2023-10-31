package com.cos.jwt.repository;


import com.cos.jwt.model.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RefreshTokenRepository  extends JpaRepository<RefreshToken, String> {
    Optional<RefreshToken> findByKey(String key);

    Optional<RefreshToken> findByValue(String value);
}
