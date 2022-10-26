package com.cos.jwt.config;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.cos.jwt.filter.MyFilter1;
import com.cos.jwt.filter.MyFilter2;


// SecurityConfig의 filterChain에 등록할 필요 없이 따로 filter 설정. 하지만 security filter 적용이 끝난 후에 해당 필터가 적용됨. SecurityConfig에 설정할 떄 before, after든 상관없이 다 끝나고 나서 실행됨.
// SecurityConfig에서 filter 적용은 security filter 내의 여러개 필터 중 그 안에서 어디에 위치시킬지 결정할 수 있음.
@Configuration
public class FilterConfig {

	@Bean
	public FilterRegistrationBean<MyFilter1> filter1() {
		FilterRegistrationBean<MyFilter1> bean = new FilterRegistrationBean<MyFilter1>(new MyFilter1());
		bean.addUrlPatterns("/*");
		bean.setOrder(0);	// 낮은 번호가 필터중에서 가장 먼저 실행됨.
		return bean;
	}
	
	@Bean
	public FilterRegistrationBean<MyFilter2> filter2() {
		FilterRegistrationBean<MyFilter2> bean = new FilterRegistrationBean<MyFilter2>(new MyFilter2());
		bean.addUrlPatterns("/*");
		bean.setOrder(1);	// 낮은 번호가 필터중에서 가장 먼저 실행됨.
		return bean;
	}
	
}
