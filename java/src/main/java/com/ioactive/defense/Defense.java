package com.ioactive.defense;

import static com.ioactive.defense.util.StringsListsUtils.containsIgnoreCase;
import static com.ioactive.defense.util.StringsListsUtils.isContainedIgnoringCase;

import java.io.File;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang3.StringUtils;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Maps;
import com.ioactive.defense.persistence.DefensePersistenceInterface;
import com.ioactive.defense.persistence.SQLiteDefensePersistence;
import com.ioactive.defense.util.ParameterMapSerializer;

public class Defense {

	public static final int OK = 1;
	public static final int ERROR = 0;
	public static final int ATTACK = -1;
	public static final int BAN = 100;
	public static final boolean DEBUG = true;
	public static final String DB = "attackers.db";
	public static final String NEWLINE = System.getProperty("line.separator");
	public static final String EMPTY = "";
	public static final String PROTOCOL = "HTTP/1.1";

	private static final DateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");

	private static final Map<String, String> SESSION_PARAMETERS = ImmutableMap.<String, String> of("user", "user", "REMOTE_ADDR", "ip", "cookie", "cookie");

	public DefensePersistenceInterface persistence = new SQLiteDefensePersistence();
	private Integer maximumRequestsPerMinute = 100;
	private Integer executionTimeWindow = 1; // Seconds
	private String cookieName = "admin";
	private String cookieValue = "false";
	private String fakeInputName = "_auth";
	private String fakeInputValue = "disabled";

	private String secretAdminAccount = "secrethiddenadminaccount";
	private String secretHiddenDirectory = "secrethiddendirectory";

	public Defense() {
	}

	public Defense(DefensePersistenceInterface defensePersistenceInterface) {
		persistence = defensePersistenceInterface;
	}

	public void setPersistence(DefensePersistenceInterface persistence) {
		this.persistence = persistence;
	}

	public void setMaximumRequestsPerMinute(Integer maximumRequestsPerMinute) {
		this.maximumRequestsPerMinute = maximumRequestsPerMinute;
	}

	public void setExecutionTimeWindow(Integer executionTimeWindow) {
		this.executionTimeWindow = executionTimeWindow;
	}

	public void setCookieName(String cookieName) {
		this.cookieName = cookieName;
	}

	public void setCookieValue(String cookieValue) {
		this.cookieValue = cookieValue;
	}

	public void setFakeInputName(String fakeInputName) {
		this.fakeInputName = fakeInputName;
	}

	public void setFakeInputValue(String fakeInputValue) {
		this.fakeInputValue = fakeInputValue;
	}

	public void setSecretAdminAccount(String secretAdminAccount) {
		this.secretAdminAccount = secretAdminAccount;
	}

	public void setSecretHiddenDirectory(String secretHiddenDirectory) {
		this.secretHiddenDirectory = secretHiddenDirectory;
	}

	/*
	 * metodos pendientes 1- function checkFakeCookie($cookie_name = "admin", $cookie_value = "false") 2 - function
	 * checkFakeInput($input, $value) 3 - function checkSpeed() 4 - function exception_handler($exception) 5-
	 * logoutSession (esta solo definido) 6 - function isAttacker() 7 - function nonExistingFile()
	 */

	/**
	 * Check that the user is using the correct HTTP method
	 * 
	 * @param request
	 * @param checkMethod
	 * @return
	 */
	public int checkHttpMethod(HttpServletRequest request, String checkMethod) {
		String attack = "Incorrect HTTP method";
		Integer score = 25;

		String method = request.getMethod();

		if (StringUtils.isBlank(method)) {
			return ERROR;
		}

		if (StringUtils.isBlank(checkMethod)) {
			List<String> results = persistence.getAcceptedMethods();
			if (containsIgnoreCase(results, method)) {
				return OK;
			} else {
				attack = "Blacklisted HTTP method";
				attackDetected(request, attack, score);
				return ATTACK;
			}
		} else {
			if (checkMethod.equalsIgnoreCase(method)) {
				return OK;
			} else {
				attackDetected(request, attack, score);
				return ATTACK;
			}
		}
	}

	/**
	 * Check if the URL contains a string flagged as an attacker
	 * 
	 * @param request
	 * @return
	 */
	public int checkURI(HttpServletRequest request) {
		String attack = "Vulnerability scanner in URL";
		int score = 10;

		String requestURI = request.getRequestURI();

		if (StringUtils.isBlank(requestURI))
			return ERROR;

		List<String> deniedURLs = persistence.getDenyURLs();
		if (isContainedIgnoringCase(deniedURLs, requestURI)) {
			attackDetected(request, attack, score);
			return ATTACK;
		}
		return OK;
	}

	/**
	 * 
	 * @param request
	 * @return
	 */
	public int checkUserAgent(HttpServletRequest request) {
		String attack = "Vulnerability scanner in user-agent";
		String requestUserAgent = request.getHeader("User-Agent");
		String sessionUserAgent = (String) request.getSession().getAttribute("HTTP_USER_AGENT");
		int score = 100;

		if (requestUserAgent == null) {
			return ERROR;
		}

		List<String> deniedUserAgents = persistence.getDeniedUserAgents();
		if (containsIgnoreCase(deniedUserAgents, requestUserAgent)) {
			attackDetected(request, attack, score);
			return ATTACK;
		}

		if (sessionUserAgent != null && requestUserAgent != null && !sessionUserAgent.equals(requestUserAgent)) {
			attack = "User-agent changed during user session";
			attackDetected(request, attack, score);
			return ATTACK;
		}
		return OK;
	}

	public int checkHTTPVersion(HttpServletRequest request) {
		String attack = "Incorrect HTTP Version";
		String protocol = request.getProtocol();
		int score = 100;

		if (protocol != null) {
			if (!protocol.equals(PROTOCOL)) {
				attackDetected(request, attack, score);
				return ATTACK;
			}
		} else
			return ERROR;
		return OK;
	}

	public int checkConcurrentSession(HttpServletRequest request) {
		String attack = "The IP address of the user changed for the cookie";
		int score = 25;

		String remoteAddress = request.getRemoteAddr();
		String sessionRemoteAddress = (String) request.getSession().getAttribute("REMOTE_ADDR");

		if (remoteAddress != null && sessionRemoteAddress != null) {
			if (!remoteAddress.equals(sessionRemoteAddress)) {
				attackDetected(request, attack, score);
				return ATTACK;
			}
		} else
			return ERROR;
		return OK;
	}

	public int checkHostname(HttpServletRequest request) {
		String attack = "Incorrect hostname";
		int score = 100;

		String requestHostName = request.getServerName();
		String sessionHostName = (String) request.getSession().getAttribute("HTTP_HOST");

		if (requestHostName != null) {
			if (sessionHostName == null) {
				sessionHostName = requestHostName;
				request.getSession().setAttribute("HTTP_HOST", requestHostName);
			}
			if (requestHostName == null || !requestHostName.equals(sessionHostName)) {
				attackDetected(request, attack, score);
				return ATTACK;
			}
		} else
			return ERROR;

		return OK;
	}

	/**
	 * Define a cookie to the user, that in case it is changed, it will be flagged as an attacker
	 * 
	 * @return
	 */
	public int checkFakeCookie(HttpServletRequest request, HttpServletResponse response) {
		String attack = "False cookie modified";
		int score = 100;

		Cookie[] cookies = request.getCookies();
		Cookie cookie = null;
		for (Cookie cookieItem : cookies) {
			if (StringUtils.equals(cookieItem.getName(), cookieName)) {
				cookie = cookieItem;
				break;
			}
		}

		if (cookie != null && !StringUtils.equals(cookie.getValue(), cookieValue)) {
			attackDetected(request, attack, score);
			return ATTACK;
		} else {
			response.addCookie(new Cookie(this.cookieName, this.cookieValue));
			return OK; // or error..
		}

	}

	/**
	 * Define a fake input field in a form and save the fake value in the session. If it is changed, consider it an
	 * attack.
	 * 
	 * @return
	 */
	public int checkFakeInput(HttpServletRequest request, String input, String value) {
		String attack = "Fake input modified";
		int score = 100;

		if (StringUtils.isEmpty(input))
			return ERROR;
		String inputValue = request.getParameter(input);

		if (!StringUtils.equals(value, inputValue)) {
			attackDetected(request, attack, score);
			return ATTACK;
		}
		return OK;
	}

	/**
	 * Define a fake input field in a form and save the fake value in the session. If it is changed, consider it an
	 * attack. This one uses the lib's set input names and values
	 * 
	 * @return
	 */
	public int checkFakeInput(HttpServletRequest request) {
		String attack = "Fake input modified";
		int score = 100;

		String inputValue = request.getParameter(fakeInputName);
		if (!StringUtils.equals(fakeInputValue, inputValue)) {
			attackDetected(request, attack, score);
			return ATTACK;
		}
		return OK;
	}

	/**
	 * Check how many requests per minute the user sends
	 * 
	 * @return
	 */
	public int checkSpeed(HttpServletRequest request) {
		String attack = "Too many requests";
		int score = 100;

		Date now = new Date();
		Calendar calendar = new GregorianCalendar();
		calendar.setTime(now);
		calendar.add(Calendar.MINUTE, -1);

		HttpSession session = request.getSession();
		Date requestLastMinute = (Date) session.getAttribute("requests_last_minute");

		if (requestLastMinute == null || requestLastMinute.before(calendar.getTime())) {
			session.setAttribute("requests_last_minute", now);
			session.setAttribute("amount_requests_last_minute", Integer.valueOf(0));
		}

		Integer requestCountForTheLastMinute = (Integer) session.getAttribute("amount_requests_last_minute");
		requestCountForTheLastMinute++;
		if (requestCountForTheLastMinute > maximumRequestsPerMinute) {
			attackDetected(request, attack, score);
			return ATTACK;
		}
		session.setAttribute("amount_requests_last_minute", requestCountForTheLastMinute);
		return OK;
	}

	/**
	 * Catch unhandled exceptions
	 * 
	 * @return
	 */
	public int exceptionHandler(HttpServletRequest request, Exception exception) {
		String attack = "Uncaught exception.";
		Integer score = 100;

		String attackDescription = String.format("%s Exception message: %s", attack, exception.getMessage());
		attackDetected(request, attackDescription, score);
		return ATTACK;
	}

	/**
	 * If tries to get to inexistante file
	 * 
	 * @return
	 */
	public int nonExistingFile() {
		// no sense for java
		return OK;
	}

	public int checkPath(HttpServletRequest request, String file) {
		File f = new File(file);
		try {
			String absoluteFile = f.getAbsolutePath();
			String canonicalFile = f.getCanonicalPath();
			if (!absoluteFile.equals(canonicalFile)) {
				attackDetected(request, "Path traversal detected", 100);
				return ATTACK;
			} else
				return OK;
		} catch (Exception e) {
			return ERROR;
		}
	}

	public int checkFakeSecretAdminAccountLeakage(HttpServletRequest request, String responseBody) {
		if (responseBody == null) {
			return ERROR;
		}
		if (responseBody.contains(secretAdminAccount)) {
			attackDetected(request, "Passwords leaked", 100);
			return ATTACK;
		}
		return OK;

	}

	public int checkFakeSecretHiddenDirectoryLeakage(HttpServletRequest request, String responseBody) {
		if (responseBody == null) {
			return ERROR;
		}
		if (responseBody.contains(secretHiddenDirectory)) {
			attackDetected(request, "Files leaked", 100);
			return ATTACK;
		}
		return OK;
	}

	public int checkExecutionTime(HttpServletRequest httpRequest, Date startTime) {
		if (startTime == null) {
			return ERROR;
		}
		Calendar c = new GregorianCalendar();
		c.add(Calendar.SECOND, executionTimeWindow * -1);
		if ((startTime.before(c.getTime()))) {// if it takes more than 1 seconds..
			attackDetected(httpRequest, "Too much time", 20);
			return ATTACK;
		}
		return OK;
	}

	// ---------------------------- common methods ----------------------------
	/**
	 * Save the attack...
	 * 
	 * @param request
	 * @param attack
	 * @param score
	 */
	public void attackDetected(HttpServletRequest request, String attack, int score) {

		Map<String, Object> sessionParameters = getSessionParameters(request.getSession());
		String serializedParameterMap = ParameterMapSerializer.serializeParameterMap(request.getParameterMap());
		// String serializedParameterMap = Dumper.dump(request.getParameterMap());

		Map<String, Object> args = Maps.newLinkedHashMapWithExpectedSize(10);
		args.put("timestamp", DATE_FORMAT.format(new Date())); // better than: args.put("timestamp", new Date());
		args.put("application", "test-defense");
		args.put("ip", sessionParameters.get("ip"));
		args.put("user", sessionParameters.get("user"));
		args.put("cookie", sessionParameters.get("cookie"));
		args.put("uri", request.getRequestURI());
		args.put("parameter", serializedParameterMap);
		args.put("attack", attack);
		args.put("score", score);

		persistence.logAttack(args);
		logoutSession(request);

		StringBuilder alertInfoBuilder = new StringBuilder();
		alertInfoBuilder.append("The last attack from the user was: ").append(attack);
		if (score >= BAN) {
			alertInfoBuilder.append(". The user was automatically mark as an attacker.");
		} else {
			alertInfoBuilder.append(". The user was mark as an attacker because of a series of events.");
		}
		alertInfoBuilder.append(NEWLINE);

		alertInfoBuilder.append("Attacker details:").append(NEWLINE);
		alertInfoBuilder.append("IP: ").append(args.get("ip")).append(NEWLINE);
		alertInfoBuilder.append("User: ").append(args.get("user")).append(NEWLINE);
		alertInfoBuilder.append("Cookie: ").append(args.get("cookie")).append(NEWLINE);
		// No sense to have this in java... perhaps the stack might help little more.
		// alertInfoBuilder.append("File: N/A").append(NEWLINE);
		alertInfoBuilder.append("URI: ").append(args.get("uri")).append(NEWLINE);
		alertInfoBuilder.append("Parameter: ").append(args.get("parameter")).append(NEWLINE);

		alertAdmin(alertInfoBuilder.toString());
	}

	/**
	 * Logout user and destroy the session
	 */
	private void logoutSession(HttpServletRequest request) {
		// TODO Auto-generated method stub
	}

	/**
	 * Get the session stuff: IP, user (optional), cookie (optional)
	 * 
	 * @param session
	 * @return
	 */
	private Map<String, Object> getSessionParameters(HttpSession session) {
		Map<String, Object> sessionParameters = Maps.newLinkedHashMap();
		Enumeration<String> attributeNames = session.getAttributeNames();
		while (attributeNames.hasMoreElements()) {
			String attributeName = attributeNames.nextElement();
			if (SESSION_PARAMETERS.containsKey(attributeName)) {
				sessionParameters.put(SESSION_PARAMETERS.get(attributeName), session.getAttribute(attributeName));
			}
		}
		return sessionParameters;
	}

	/**
	 * Provide an alert
	 * 
	 * @param alertInfo
	 */
	public void alertAdmin(String alertInfo) {
		if (DEBUG)
			System.out.println(String.format("%s%s", alertInfo, NEWLINE));
	}

}