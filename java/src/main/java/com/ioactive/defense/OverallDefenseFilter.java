package com.ioactive.defense;

import java.io.IOException;
import java.util.Date;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.ioactive.defense.response.HttpServletResponseCopier;

public class OverallDefenseFilter
	implements Filter {

	private final Defense defense = new Defense();

	@Override
	public void destroy() {
	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) throws ServletException, IOException {
		System.out.print("filtering request...");
		if (!(resp instanceof HttpServletResponse)) {
			throw new ServletException("This filter only supports HTTP");
		}

		if (req instanceof HttpServletRequest) {
			HttpServletRequest httpRequest = (HttpServletRequest) req;
			int methodAttack = defense.checkHttpMethod(httpRequest, null);
			int uriAttack = defense.checkURI(httpRequest);
			int userAgentAttack = defense.checkUserAgent(httpRequest);
			int httpVersionAttack = defense.checkHTTPVersion(httpRequest);
			int concurrentSessionAttack = defense.checkConcurrentSession(httpRequest);
			int hostnameAttack = defense.checkHostname(httpRequest);
			int speedAttack = defense.checkSpeed(httpRequest);
			if ((methodAttack == Defense.ATTACK || uriAttack == Defense.ATTACK || userAgentAttack == Defense.ATTACK || httpVersionAttack == Defense.ATTACK
				|| concurrentSessionAttack == Defense.ATTACK || hostnameAttack == Defense.ATTACK || speedAttack == Defense.ATTACK)) {
				throw new RuntimeException("Attack detected"); // <--- Aquí hay que decidir qué se lanza, pero de este
																// modo no ejecutaría el servlet invocado
			}
			try {
				Date startTime = new Date();

				HttpServletResponseCopier responseCopier = new HttpServletResponseCopier((HttpServletResponse) resp);

				chain.doFilter(req, responseCopier);

				responseCopier.flushBuffer();
				byte[] copy = responseCopier.getCopy();
				String responseBody = new String(copy, resp.getCharacterEncoding());
				System.out.println(responseBody); // See what this does
				int passLeakAttack = defense.checkFakeSecretAdminAccountLeakage(httpRequest, responseBody);
				int hiddenDirectoryLeakAttack = defense.checkFakeSecretHiddenDirectoryLeakage(httpRequest, responseBody);
				int executionTimeAttack = defense.checkExecutionTime(httpRequest, startTime);
				if (passLeakAttack == Defense.ATTACK || hiddenDirectoryLeakAttack == Defense.ATTACK || executionTimeAttack == Defense.ATTACK) {
					throw new RuntimeException("Attack detected"); // <--- Aquí hay que decidir qué se lanza, pero de
																	// este modo no ejecutaría el servlet invocado
				}
			} catch (Exception e) {
				defense.exceptionHandler(httpRequest, e);
			}
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
