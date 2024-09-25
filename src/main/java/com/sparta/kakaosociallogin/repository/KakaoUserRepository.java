package com.sparta.kakaosociallogin.repository;

import com.sparta.kakaosociallogin.entity.KakaoUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface KakaoUserRepository extends JpaRepository<KakaoUser, Long> {
    Optional<KakaoUser> findBySocialIdAndSocialType(String socialId, String kakao);
}
