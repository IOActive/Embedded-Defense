package com.ioactive;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ProtectedServlet
	extends HttpServlet {

	private static final String htmlPath = "safe.html";

	private static final long serialVersionUID = 1L;

	private final File html = new File(getClass().getClassLoader().getResource(htmlPath).getFile());

	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		response.setContentType("text/html");
		response.setStatus(HttpServletResponse.SC_OK);

		System.out.println(String.format("File path: '%s'", html.getAbsolutePath()));
		if (html.exists()) {
			try (BufferedReader br = new BufferedReader(new FileReader(html))) {
				String line;
				while ((line = br.readLine()) != null) {
					response.getWriter().println(line);
				}
			}
		} else {
			response.getWriter().println("<h1>Safe area.</h1>");
		}
		response.getWriter().println("session=" + request.getSession(true).getId());
	}

	@Override
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		response.setContentType("text/html");
		response.setStatus(HttpServletResponse.SC_OK);

		File html = new File(htmlPath);
		if (html.exists()) {
			try (BufferedReader br = new BufferedReader(new FileReader(html))) {
				String line;
				while ((line = br.readLine()) != null) {
					response.getWriter().println(line);
				}
			}
		} else {
			response.getWriter().println("<h1>Safe area.</h1>");
		}
		response.getWriter().println("session=" + request.getSession(true).getId());
	}
}