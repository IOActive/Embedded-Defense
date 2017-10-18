package com.ioactive.defense;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class FakeCookieDefenseFilter
	implements Filter {

	private final Defense defense = new Defense();

	@Override
	public void destroy() {
	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) throws ServletException, IOException {
		System.out.print("filtering request...");
		if (req instanceof HttpServletRequest) {
			HttpServletRequest httpRequest = (HttpServletRequest) req;
			defense.checkFakeCookie(httpRequest, (HttpServletResponse) resp);
			chain.doFilter(req, resp);
		} else {
			// Si no es un http request, sino otro tipo, se podría rechazar, lanzar una excepción, o simplemente dejar
			// pasar
			chain.doFilter(req, resp);
		}
	}

	@Override
	public void init(FilterConfig config) throws ServletException {
		System.out.print("Init...");
	}

}
