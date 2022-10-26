package com.cos.jwt.filter;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class MyFilter3 implements Filter{

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		
		HttpServletRequest req = (HttpServletRequest) request;
		HttpServletResponse res = (HttpServletResponse) response;
		
		// token 보통 header에 Authorization에 들어있음. 간단하게 token을 만들어서 test
		// token : cos를 만들어주어야 함. id, pw가 정상적으로 들어와서 로그인이 완료되면 토큰을 만들어주고 그걸 응답해준다.
		// 요청할 때마다 header에 Authorization에 value값으로 토큰을 가지오 옴. 이떄 token이 넘어오면 이 토큰이 내가 만든 토큰이 맞는지만 검증하면 됨.(RSA, HS256)
		if (req.getMethod().equals("POST")) {
			String headerAuth = req.getHeader("Authorization");
			System.out.println("headerAuth : " + headerAuth);
			
			if (headerAuth.equals("cos") ) {
				chain.doFilter(req, res);
			}else {
				PrintWriter out = res.getWriter();
				out.println("인증안됨");
			}
		}
	}
	
}
