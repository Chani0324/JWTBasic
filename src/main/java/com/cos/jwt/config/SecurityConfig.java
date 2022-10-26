package com.cos.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.filter.CorsFilter;

import com.cos.jwt.config.jwt.JwtAuthenticationFilter;
import com.cos.jwt.config.jwt.JwtAuthorizationFilter;
import com.cos.jwt.config.repository.JWTUserRepository;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity	// spring security 필터가 spring filterChain에 등록이 됨.
@RequiredArgsConstructor
public class SecurityConfig {
	
	private final CorsFilter corsFilter;
	
	private final CorsConfig corsConfig;
	
	private final JWTUserRepository userRepository;
	
	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
	    
		return http
//				.addFilterBefore(new MyFilter3(), SecurityContextHolderFilter.class)	// filter chain중 어디에 적용할건지 알아야 함. security가 동작되기 전 MyFilter3 적용.
																						// SecurityContextPersistenceFilter가 deprecated 되었고
																						// SecurityContextHolderFilter를 Security filter 제일 먼저 사용.
				.csrf().disable()
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)	// session 정보 사용 안함 (JWT 사용하기 위한 설정)
				.and()
				.formLogin().disable()
				.httpBasic().disable()	// http방식 중 기본적으로 header의 Authorization key값에 id, pw가 들어가게 되는데 이는 보안이 되지 않은 상태로 전송됨(https를 쓰면 암호화가 되긴 함). 
										// JWT를 쓰려면 이 key값에 token을 넣어줄거기 때문에(이를 bearer 방식이라고 함) disable 설정.
				.apply(new MyCustomDsl()) // 커스텀 필터 등록
				.and()
				.authorizeRequests(authorize -> authorize
						.antMatchers("/api/v1/user/**")
						.access("hasRole('ROLE_USER') or hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
						.antMatchers("/api/v1/manager/**")
						.access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
						.antMatchers("/api/v1/admin/**")
						.access("hasRole('ROLE_MANAGER')")
						.anyRequest().permitAll())
				.build();
				
	}
	
	public class MyCustomDsl extends AbstractHttpConfigurer<MyCustomDsl, HttpSecurity> {
		@Override
		public void configure(HttpSecurity http) throws Exception {
			AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
			http
					.addFilter(corsConfig.corsFilter())
					.addFilter(new JwtAuthenticationFilter(authenticationManager))
					.addFilter(new JwtAuthorizationFilter(authenticationManager, userRepository));
		}
	}
}
