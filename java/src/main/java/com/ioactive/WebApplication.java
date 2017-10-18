package com.ioactive;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.builder.ReflectionToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.AbstractHandler;

public class WebApplication
	extends AbstractHandler {

	public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {

		System.out.println(String.format("target: %s", target));
		// System.out.println(String.format("baseRequest: %s", Dumper.dump(baseRequest, 10, 100, null)));
		System.out.println(String.format("baseRequest: %s", ReflectionToStringBuilder.toString(baseRequest, ToStringStyle.MULTI_LINE_STYLE)));
		// System.out.println(String.format("request: %s", Dumper.dump(request, 10, 100, null)));
		System.out.println(String.format("request: %s", ReflectionToStringBuilder.toString(request, ToStringStyle.MULTI_LINE_STYLE)));
		// System.out.println(String.format("response: %s", Dumper.dump(response, 10, 100, null)));
		System.out.println(String.format("response: %s", ReflectionToStringBuilder.toString(response, ToStringStyle.MULTI_LINE_STYLE)));

		response.setContentType("text/html;charset=utf-8");
		response.setStatus(HttpServletResponse.SC_OK);
		baseRequest.setHandled(true);
		response.getWriter().println("<h1>Hello World</h1>");
	}

	public static void main(String[] args) throws Exception {
		Server server = new Server(8080);
		server.setHandler(new WebApplication());

		server.start();
		server.join();
	}
}
