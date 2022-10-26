package com.cos.jwt.config.jwt;

import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.config.repository.JWTUserRepository;
import com.cos.jwt.model.JWTUser;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;


// Spring Security에서 UsernamePasswordAuthenticationFilter가 있음.
// /login으로 요청해서 username, password 전송하면 (post)
// UsernamePasswordAuthenticationFilter 동작을 함.
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter{

	private final AuthenticationManager authenticationManager;
	
	private JWTUserRepository userRepository;
	
	// /login 요청을 하면 로그인 시도를 위해서 실행되는 함수.
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		
		System.out.println("JwtFilter : 로그인 시도중");
		
		// 1. username, password 받아서
		try {
//			BufferedReader br = request.getReader();
//			
//			String input = null;
//			
//			while((input=br.readLine()) != null) {
//			System.out.println("===================================");
//			System.out.println(input);
//			}
			
			ObjectMapper om = new ObjectMapper();
			JWTUser user = om.readValue(request.getInputStream(), JWTUser.class);
			System.out.println(user);
			
			UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
			System.out.println(authenticationToken);
			
			// authenticate() 함수가 호출 되면 인증 프로바이더가 유저 디테일 서비스의
			// loadUserByUsername(토큰의 첫번째 파라메터) 를 호출하고
			// UserDetails를 리턴받아서 토큰의 두번째 파라메터(credential)과
			// UserDetails(DB값)의 getPassword()함수로 비교해서 동일하면
			// Authentication 객체를 만들어서 필터체인으로 리턴해준다.
			
			// Tip: 인증 프로바이더의 디폴트 서비스는 UserDetailsService 타입
			// Tip: 인증 프로바이더의 디폴트 암호화 방식은 BCryptPasswordEncoder
			// 결론은 인증 프로바이더에게 알려줄 필요가 없음.
			Authentication authentication = authenticationManager.authenticate(authenticationToken);
			
			// 로그인이 되었으면 principalDeatils에서 정보를 가져올 수 있음.
			PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
			System.out.println("로그인 완료 : " + principalDetails.getUser().getUsername());
			
			// authentication 객체가 session 영역에 저장되려면 return해주면 됨.
			// return의 이유는 권한 관리는 security가 대신 해주기 때문에 편하려고 하는것임.
			// JWT를 사용하면서 세션을 만들 이유가 없음. 단지 권한 처리 때문에 session에 넣어준다.
			return authentication;
			
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		// 2. 정상인지 로그인 시도. authenticationManager로 로그인 시도를 하면 PrincipalDetailsService가 호출 -> loadUserByUsername method가 자동적 실행
		
		// 3. PrincipalDetails를 세션에 저장. -> 세션에 담지 않으면 권한 관리가 되지 않음. 권한 관리를 하지 않을거면 session에 담을 필요는 없음.
		
		// 4. JWT토큰을 만들어서 응답.
		return null;
	}
	
	// attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행됨.
	// JWT 토큰을 만들어서 request요청한 사용자에게 JWT토큰을 response 해주면 됨.
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		
		PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
		
		System.out.println("successfulAuthentication 실행됨. 인증이 완료 되었다는 뜻임.");
		
		// RSA방식이 아닌 Hash암호방식
		String jwtToken = JWT.create()
				.withSubject("cos토큰")	// 토큰 이름. 큰 의미는 없음.
				.withExpiresAt(new Date(System.currentTimeMillis()+JwtProperties.EXPIRATION_TIME))	// 토큰 만료 시간((1분) * 10)
				.withClaim("id", principalDetails.getUser().getId())	// 내가 넣고 싶은 비공개 key와 value 값
				.withClaim("username", principalDetails.getUser().getUsername())	// 내가 넣고 싶은 비공개 key와 value 값
				.sign(Algorithm.HMAC512(JwtProperties.SECRET));
		
		response.addHeader("Authorization", "Bearer " + jwtToken);;
	}
}
