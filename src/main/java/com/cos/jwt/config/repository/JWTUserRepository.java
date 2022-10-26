package com.cos.jwt.config.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.cos.jwt.model.JWTUser;

public interface JWTUserRepository extends JpaRepository<JWTUser, Long>{
	
	public JWTUser findByUsername(String username);
	
}
