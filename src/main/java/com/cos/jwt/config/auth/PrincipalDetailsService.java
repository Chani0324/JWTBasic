package com.cos.jwt.config.auth;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.cos.jwt.config.repository.JWTUserRepository;
import com.cos.jwt.model.JWTUser;

import lombok.RequiredArgsConstructor;

// http://localhost:8081/login 요청이 올 때 동작 -> SecurityConfig에 formLogin을 disable했으므로 기본 /login 주소가 없음.
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService{
	
	private final JWTUserRepository userRepsitory;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		System.out.println("PrincipalDetailsService의 loadUserByUsername");
		JWTUser userEntity = userRepsitory.findByUsername(username);
		
		return new PrincipalDetails(userEntity);
	}
	
	
}
