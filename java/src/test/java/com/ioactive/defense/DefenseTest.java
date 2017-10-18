package com.ioactive.defense;

import static com.ioactive.defense.persistence.SQLiteDefensePersistence.SQLITE_DB_NAME;

import java.io.File;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang3.StringUtils;
import org.mockito.Mock;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.util.CollectionUtils;
import org.testng.Assert;
import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

import com.ioactive.defense.persistence.DefensePersistenceInterface;
import com.ioactive.defense.persistence.SQLiteDefensePersistence;

public class DefenseTest {

	private static final String GET_METHOD = "get";
	private static final String INVALID_METHOD = "not_valid";

	private static final String PUBLIC_IP = "127.0.0.1";
	private static final String ALTERED_IP = "1.1.1.1";

	private int count = 1;

	private final File db = new File(SQLITE_DB_NAME);
	private final File dbBackup = new File(String.format("%s.bkp", SQLITE_DB_NAME));
	private final File testDb = new File(String.format("test-%s", SQLITE_DB_NAME));

	@Mock
	private DefensePersistenceInterface persistence;
	private Defense defense;

	private MockHttpServletRequest getBaseRequestForTest() {
		MockHttpServletRequest mockRequest = new MockHttpServletRequest();
		mockRequest.setRemoteAddr(PUBLIC_IP);
		HttpSession session = mockRequest.getSession();
		session.setAttribute("REMOTE_ADDR", PUBLIC_IP);
		// session.setAttribute("user", "defense-test");
		return mockRequest;
	}

	private MockHttpServletRequest getRequestWithoutIPForTest() {
		MockHttpServletRequest mockRequest = new MockHttpServletRequest();
		mockRequest.setRemoteAddr(PUBLIC_IP);
		HttpSession session = mockRequest.getSession();
		session.setAttribute("user", "defense-test");
		return mockRequest;
	}

	@BeforeTest
	public void prepareBefore() {
		if (db.exists()) {
			db.renameTo(dbBackup);
		}
		persistence = new SQLiteDefensePersistence();
		defense = new Defense(persistence);
	}

	@AfterTest
	public void cleanUpAndDisplayResults() {
		List<Map<String, Object>> knownAttackers = persistence.getAttackersList();
		if (CollectionUtils.isEmpty(knownAttackers)) {
			System.out.println("No attackers registered during this test session.");
		}
		Map<String, Object> first = knownAttackers.get(0);
		Set<String> keyset = first.keySet();
		System.out.print("|");
		for (String key : keyset) {
			System.out.print(String.format("%s|", key));
		}
		System.out.println();
		for (Map<String, Object> map : knownAttackers) {
			System.out.print("|");
			for (String key : keyset) {
				System.out.print(String.format("%s|", map.get(key)));
			}
			System.out.println();
		}
		if (db.exists()) {
			db.renameTo(testDb);
		}
		if (dbBackup.exists()) {
			dbBackup.renameTo(db);
		}
	}

	/*
	 * 1) Pre-execution control: Check valid HTTP method
	 */
	@Test
	public void requestsMethodIsValid_shouldReturnOk() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		List<String> acceptedMethods = new ArrayList<>();
		acceptedMethods.add(GET_METHOD);
		// when(persistence.getAcceptedMethods()).thenReturn(acceptedMethods);
		MockHttpServletRequest request = getBaseRequestForTest();
		request.setMethod(GET_METHOD);
		int response = defense.checkHttpMethod(request, "");
		Assert.assertEquals(Defense.OK, response,
			String.format("     -=- Case %02d :: FAILURE: HTTP method was a valid one and should have turned out OK instead.", i));
		System.out.println(String.format("     -=- Case %02d :: SUCCESS: HTTP method was a valid one and attack analysis turned out OK.", i));
	}

	@Test
	public void requestsMethodMatchesExpected_shouldReturnOk() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		List<String> acceptedMethods = new ArrayList<>();
		acceptedMethods.add(GET_METHOD);
		// when(persistence.getAcceptedMethods()).thenReturn(acceptedMethods);
		MockHttpServletRequest request = getBaseRequestForTest();
		request.setMethod(GET_METHOD);
		int response = defense.checkHttpMethod(request, GET_METHOD);
		Assert.assertEquals(Defense.OK, response,
			String.format("     -=- Case %02d :: FAILURE: HTTP method was a valid and matched expected and should have turned out OK instead.", i));
		System.out.println(String.format("     -=- Case %02d :: SUCCESS: HTTP method was a valid and matched expected and attack analysis turned out OK.", i));
	}

	@Test
	public void requestsMethodIsBlank_shouldReturnError() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		MockHttpServletRequest request = getBaseRequestForTest();
		int response = defense.checkHttpMethod(request, "");
		Assert.assertEquals(Defense.ERROR, response,
			String.format("     -=- Case %02d :: FAILURE: HTTP method was blank and should have result in ERROR instead.", i));
		System.out.println(String.format("     -=- Case %02d :: SUCCESS: HTTP method was blank and result in ERROR.", i));
	}

	@Test
	public void requestsMethodDoesntMatchExpected_shouldReturnAttack() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		MockHttpServletRequest request = getBaseRequestForTest();
		request.setMethod(GET_METHOD);
		int response = defense.checkHttpMethod(request, INVALID_METHOD);
		Assert.assertEquals(Defense.ATTACK, response, String.format(
			"	 -=- Case %02d :: FAILURE: HTTP method was %s and did not match expected %s and should have result in ATTACK instead.", i, GET_METHOD,
			INVALID_METHOD));
		System.out.println(String.format("     -=- Case %02d :: SUCCESS: HTTP method was %s and did not match expected %s and result in ATTACK.", i,
			INVALID_METHOD, GET_METHOD));
	}

	@Test
	public void requestsMethodIsNotAccepted_shouldReturnAttack() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		List<String> acceptedMethods = new ArrayList<>();
		acceptedMethods.add(GET_METHOD);
		// when(persistence.getAcceptedMethods()).thenReturn(acceptedMethods);
		MockHttpServletRequest request = getBaseRequestForTest();
		request.setMethod(INVALID_METHOD);
		int response = defense.checkHttpMethod(request, null);
		Assert.assertEquals(Defense.ATTACK, response, String.format(
			"	 -=- Case %02d :: FAILURE: HTTP method %s does not exist among accepted methods and should have result in ATTACK instead.", i, INVALID_METHOD));
		System.out.println(String.format("     -=- Case %02d :: SUCCESS: HTTP method %s does not exist among accepted methods and result in ATTACK.", i,
			INVALID_METHOD));
	}

	/*
	 * END) Pre-execution control: Check valid HTTP method
	 */

	/*
	 * 2) Pre-execution control: Check if the URL contains a vulnerability scanner string
	 */
	@Test
	public void urlIsNotDenied_shouldReturnOk() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		MockHttpServletRequest request = getBaseRequestForTest();
		List<String> denyURLs = new ArrayList<>();
		denyURLs.add("DENY_URL");
		// when(persistence.getDenyURLs()).thenReturn(denyURLs);
		request.setRequestURI("google.com");
		int response = defense.checkURI(request);
		Assert.assertEquals(Defense.OK, response, String.format("     -=- Case %02d :: FAILURE: URL is not denieable and should return OK instead.", i));
		System.out.println(String.format("     -=- Case %02d :: SUCCESS: URL is not denieable and result was OK.", i));
	}

	@Test
	public void urlIsBlank_shouldReturnError() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		MockHttpServletRequest request = getBaseRequestForTest();
		int response = defense.checkURI(request);
		Assert.assertEquals(Defense.ERROR, response, String.format("     -=- Case %02d :: FAILURE: URL is blank and should return ERROR instead.", i));
		System.out.println(String.format("     -=- Case %02d :: SUCCESS: URL is blank and result was ERROR.", i));
	}

	@Test
	public void urlContainsDeniedString_shouldReturnAttack() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		String requestURI = "http://someurl/nikto";

		MockHttpServletRequest request = getBaseRequestForTest();
		request.setRequestURI(requestURI);
		int response = defense.checkURI(request);
		Assert.assertEquals(Defense.ATTACK, response,
			String.format("     -=- Case %02d :: FAILURE: URL contains denied part and ATTACK was expected instead.", i));
		System.out.println(String.format("     -=- Case %02d :: SUCCESS: URL <%s> contains denied part <%s> and returned ATTACK.", i, requestURI, "nikto"));
	}

	/*
	 * END) Pre-execution control: Check if the URL contains a vulnerability scanner string
	 */

	/*
	 * 3) Pre-execution control: Check if a valid HTTP protocol version is being used
	 */
	@Test
	public void httpProtocolIsRight_ShouldReturnOk() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		MockHttpServletRequest request = getBaseRequestForTest();
		request.setProtocol(Defense.PROTOCOL);
		int response = defense.checkHTTPVersion(request);
		Assert.assertEquals(Defense.OK, response, String.format("     -=- Case %02d :: FAILURE: HTTP protocol is right and should've returned OK instead.", i));
		System.out.println(String.format("     -=- Case %02d :: SUCCESS: HTTP protocol is right and returned OK.", i));
	}

	@Test
	public void wrongHttpProtocolVersion_ShouldReturnAttack() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		MockHttpServletRequest request = getBaseRequestForTest();
		request.setProtocol("HTTP/8.0");
		int response = defense.checkHTTPVersion(request);
		Assert.assertEquals(Defense.ATTACK, response,
			String.format("     -=- Case %02d :: FAILURE: HTTP protocol version isn't right and should've returned ATTACK.", i));
		System.out.println(String.format("     -=- Case %02d :: SUCCESS: HTTP protocol version isn't right and returned ATTACK.", i));
	}

	@Test
	public void httpProtocolIsNotDefined_ShouldReturnError() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		MockHttpServletRequest request = getBaseRequestForTest();
		request.setProtocol(null);
		int response = defense.checkHTTPVersion(request);
		Assert.assertEquals(Defense.ERROR, response,
			String.format("     -=- Case %02d :: FAILURE: HTTP protocol version isn't defined and should've returned ERROR.", i));
		System.out.println(String.format("     -=- Case %02d :: SUCCESS: HTTP protocol version isn't defined and returned ERROR.", i));
	}

	/*
	 * END) Pre-execution control: Check if a valid HTTP protocol version is being used
	 */

	/*
	 * 4) Pre-execution control: Check if the user entered the correct domain name
	 */
	@Test
	public void hostnameIsUnchanged_ShouldReturnOk() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		MockHttpServletRequest request = getBaseRequestForTest();
		request.setServerName("localhost");
		request.getSession().setAttribute("HTTP_HOST", "localhost");
		int response = defense.checkHostname(request);
		Assert.assertEquals(Defense.OK, response, String.format("     -=- Case %02d :: FAILURE: hostname was unchanged and should've returned OK.", i));
		System.out.println(String.format("     -=- Case %02d :: SUCCESS: hostname was unchanged and returned OK.", i));
	}

	@Test
	public void hostnameChanges_ShouldReturnAttack() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		MockHttpServletRequest request = getBaseRequestForTest();
		request.setServerName("localhost");
		request.addHeader("Remote_Addr", ALTERED_IP);
		request.getSession().setAttribute("HTTP_HOST", "otherHost");
		int response = defense.checkHostname(request);
		Assert.assertEquals(Defense.ATTACK, response, String.format("     -=- Case %02d :: FAILURE: hostname was changed and should've returned ATTACK.", i));
		System.out.println(String.format("     -=- Case %02d :: SUCCESS: hostname was changed and returned ATTACK.", i));
	}

	@Test
	public void hostnameIsUndefined_ShouldReturnError() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		MockHttpServletRequest request = getBaseRequestForTest();
		request.setServerName(null);
		int response = defense.checkHostname(request);
		Assert.assertEquals(Defense.ERROR, response, String.format("     -=- Case %02d :: FAILURE: hostname was undefined and should've returned ERROR.", i));
		System.out.println(String.format("     -=- Case %02d :: SUCCESS: hostname was undefined and returned ERROR.", i));
	}

	/*
	 * END) Pre-execution control: Check if the user entered the correct domain name
	 */

	/*
	 * 5) Pre-execution control: Forced browsing: invalid URI. When attack is detected this method is called through the
	 * filters
	 */
	@Test
	public void forcedBrowsing_ShouldLogAttack() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		MockHttpServletRequest request = getBaseRequestForTest();
		defense.attackDetected(request, "Invalid URI (potential path traversal)", 20);
		System.out.println(String.format("     -=- Case %02d :: No assertions", i));
	}

	/*
	 * 6 & 7 ) Defense not implemented
	 */

	/*
	 * 8) Pre-execution control: Forced browsing: check if a non-authenticated user is accessing a privileged resource
	 * without permission
	 */
	@Test
	public void unauthenticatedUser_ShouldLogAttack() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		MockHttpServletRequest request = getBaseRequestForTest();
		defense.attackDetected(request, "Existing resource accessed by a non-authenticated user", 20);
		System.out.println(String.format("     -=- Case %02d :: No assertions", i));
	}

	/*
	 * 9) Pre-execution control: Forced browsing: check if an authenticated user is accessing a privileged resource
	 * without permission
	 */
	@Test
	public void unauthorizedUser_ShouldLogAttack() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		MockHttpServletRequest request = getBaseRequestForTest();
		defense.attackDetected(request, "Authenticated user without permission", 100);
		System.out.println(String.format("     -=- Case %02d :: No assertions", i));
	}

	/*
	 * 10) Pre-execution control: Check if the User-Agent is a vulnerability scanner
	 */
	@Test
	public void userAgentIsNotKnownToBeAnAttacker_shouldReturnOk() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		MockHttpServletRequest request = getBaseRequestForTest();
		request.addHeader("User-Agent", "USER2");
		request.getSession().setAttribute("HTTP_USER_AGENT", "USER2");
		int response = defense.checkUserAgent(request);
		Assert.assertEquals(Defense.OK, response, String.format("     -=- Case %02d :: FAILURE: UserAgent was not an attacker and should've returned OK.", i));
		System.out.println(String.format("     -=- Case %02d :: SUCCESS: UserAgent was not an attacker and returned OK.", i));
	}

	@Test
	public void userAgentIsKnownToBeAnAttacker_shouldReturnAttack() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		MockHttpServletRequest request = getBaseRequestForTest();
		request.addHeader("User-Agent", "nikto");
		request.getSession().setAttribute("HTTP_USER_AGENT", "nikto");
		int response = defense.checkUserAgent(request);
		Assert
			.assertEquals(Defense.ATTACK, response, String.format("     -=- Case %02d :: FAILURE: UserAgent was an attacker and should've return ATTACK.", i));
		System.out.println(String.format("     -=- Case %02d :: SUCCESS: UserAgent was an attacker and returned ATTACK.", i));
	}

	/*
	 * END) Pre-execution control: Check if the URL contains a vulnerability scanner string
	 */

	/*
	 * 11) Pre-execution control: Check if the User-Agent has changed
	 */
	@Test
	public void userAgentIsChanged_ShouldReturnAttack() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		MockHttpServletRequest request = getBaseRequestForTest();
		request.addHeader("User-Agent", "USER2");
		request.getSession().setAttribute("HTTP_USER_AGENT", "USER1");
		request.setRemoteAddr(PUBLIC_IP);

		int response = defense.checkUserAgent(request);
		Assert.assertEquals(Defense.ATTACK, response, String.format("     -=- Case %02d :: FAILURE: UserAgent was modified and ATTACK was expected.", i));
		System.out.println(String.format("     -=- Case %02d :: SUCCESS: UserAgent was modified and returned ATTACK.", i));
	}

	@Test
	public void userAgentIsUndefined_ShouldReturnError() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		MockHttpServletRequest request = getBaseRequestForTest();
		int response = defense.checkUserAgent(request);
		Assert.assertEquals(Defense.ERROR, response, String.format("     -=- Case %02d :: FAILURE: UserAgent was undefined/null and ERROR was expected.", i));
		System.out.println(String.format("     -=- Case %02d :: SUCCESS: UserAgent was undefined/null and returned ERROR.", i));
	}

	/*
	 * END) Pre-execution control: Check if the User-Agent has changed
	 */

	/*
	 * 12) Pre-execution control: Check if the IP address changed for the cookie
	 */
	@Test
	public void ipAddressChanges_ShouldReturnAttack() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		MockHttpServletRequest request = getBaseRequestForTest();
		request.getSession().setAttribute("REMOTE_ADDR", ALTERED_IP);
		request.setRemoteAddr(PUBLIC_IP);
		int response = defense.checkConcurrentSession(request);
		Assert.assertEquals(Defense.ATTACK, response, String.format("     -=- Case %02d :: FAILURE: IP was changed and should've returned ATTACK.", i));
		System.out.println(String.format("     -=- Case %02d :: SUCCESS: IP was changed and returned ATTACK.", i));
	}

	@Test
	public void ipAddressIsUndefined_ShouldReturnError() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		MockHttpServletRequest request = getRequestWithoutIPForTest();
		request.setRemoteAddr(PUBLIC_IP);
		int response = defense.checkConcurrentSession(request);
		Assert.assertEquals(Defense.ERROR, response, String.format("     -=- Case %02d :: FAILURE: IP was undefined/null and should've returned ERROR.", i));
		System.out.println(String.format("     -=- Case %02d :: SUCCESS: IP was undefined/null and returned ERROR.", i));
	}

	/*
	 * END) Pre-execution control: Check if the IP address changed for the cookie
	 */

	/*
	 * 13) Pre-execution control: Trap: check if a user is accessing a fake robots.txt entry
	 */
	@Test
	public void accessingFakeRobots_ShouldLogAttack() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		MockHttpServletRequest request = getBaseRequestForTest();
		defense.attackDetected(request, "Fake robots.txt entry", 100);
		System.out.println(String.format("     -=- Case %02d :: No assertions", i));
	}

	/*
	 * 14) Pre-execution control: Trap: check if a user is accessing a fake hidden URL within a document
	 */
	@Test
	public void accessingFakeHiddenURLs_ShouldLogAttack() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		MockHttpServletRequest request = getBaseRequestForTest();
		defense.attackDetected(request, "Fake hidden URL access", 100);
		System.out.println(String.format("     -=- Case %02d :: No assertions", i));
	}

	// 15) Pre-execution control: Trap: check if a user is modifying a fake cookie
	@Test
	public void cookieStaysSame_ShouldReturnOk() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		MockHttpServletRequest request = getBaseRequestForTest();
		MockHttpServletResponse httpResponse = new MockHttpServletResponse();
		request.setCookies(new Cookie("admin", "false"));
		int checkResult = defense.checkFakeCookie(request, httpResponse);
		Assert.assertEquals(Defense.OK, checkResult,
			String.format("     -=- Case %02d :: FAILURE:  Test Cookie stood the same and analysis should've returned OK.", i));
		System.out.println(String.format("     -=- Case %02d :: SUCCESS: Test Cookie stoodd the same and analysis result OK.", i));

	}

	@Test
	public void cookieIsAltered_ShouldReturnAttack() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		MockHttpServletRequest request = getBaseRequestForTest();
		request.setCookies(new Cookie("admin", "true"));
		int response = defense.checkFakeCookie(request, null);
		Assert.assertEquals(Defense.ATTACK, response,
			String.format("     -=- Case %02d :: FAILURE: Test Cookie was altered and analysis should've returned ATTACK.", i));
		System.out.println(String.format("     -=- Case %02d :: SUCCESS: Test Cookie was altered and analysis result in ATTACK.", i));

	}

	// 16) Pre-execution control: Trap: check if a user is modifying a fake input field
	@Test
	public void inputStaysSame_ShouldReturnOk() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		MockHttpServletRequest request = getBaseRequestForTest();
		request.getSession().setAttribute("passkey", "674441960ca1ba2de08ad4e50c9fde98");
		request.setParameter("passkey", "674441960ca1ba2de08ad4e50c9fde98");
		int checkResult = defense.checkFakeInput(request, "passkey", "674441960ca1ba2de08ad4e50c9fde98");
		Assert.assertEquals(Defense.OK, checkResult,
			String.format("     -=- Case %02d :: FAILURE:  Test Input stood the same and analysis should've returned OK.", i));
		System.out.println(String.format("     -=- Case %02d :: SUCCESS: Test Cookie stoodd the same and analysis result OK.", i));

	}

	@Test
	public void inputIsAltered_ShouldReturnAttack() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		MockHttpServletRequest request = getBaseRequestForTest();
		request.getSession().setAttribute("passkey", "674441960ca1ba2de08ad4e50c9fde98");
		request.setParameter("passkey", "a value different than the one I am testing");
		int checkResult = defense.checkFakeInput(request, "passkey", "674441960ca1ba2de08ad4e50c9fde98");
		Assert.assertEquals(Defense.ATTACK, checkResult,
			String.format("     -=- Case %02d :: FAILURE: Test Input was altered and analysis should've returned ATTACK.", i));
		System.out.println(String.format("     -=- Case %02d :: SUCCESS: Test Input was altered and analysis result in ATTACK.", i));

	}

	// 17) Execution control: check if they are using the correct HTTP verb... why would we..?
	@Test
	public void httpMethodIsDistorted_ShouldReturnAttack() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		MockHttpServletRequest request = getBaseRequestForTest();
		request.setMethod("GET");
		int checkResult = defense.checkHttpMethod(request, "POST");
		Assert.assertEquals(Defense.ATTACK, checkResult,
			String.format("     -=- Case %02d :: FAILURE: HttpMethod doesn't match and analysis should've returned ATTACK.", i));
		System.out.println(String.format("     -=- Case %02d :: SUCCESS: HttpMethod doesn't match and analysis result ATTACK.", i));
	}

	// 18) Execution control: check if any parameter is missing
	@Test
	public void missingParameter_ShouldLogAttack() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		MockHttpServletRequest request = getBaseRequestForTest();
		if (request.getParameter("this_parameter_should_not_be_missing") == null) {
			defense.attackDetected(request, "Missing parameter", 100);
		}
		System.out.println(String.format("     -=- Case %02d :: No assertions", i));
	}

	// 19) Execution control: check if there are any extra parameters
	@Test
	public void extraParameters_ShouldLogAttack() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		MockHttpServletRequest request = getBaseRequestForTest();
		if (request.getParameterMap().size() != 999) {
			defense.attackDetected(request, "Extra parameters", 20);
		}
		System.out.println(String.format("     -=- Case %02d :: No assertions", i));
	}

	// 20) Execution control: check if they are sending unexpected values on any parameter
	@Test
	public void parameterHasUnexpectedValue_ShouldLogAttack() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		MockHttpServletRequest request = getBaseRequestForTest();
		request.setParameter("numeric_string", "alphanum3r1c");
		String id = request.getParameter("numeric_string");
		if (!StringUtils.isNumeric(id)) {
			defense.attackDetected(request, "Unexpected value", 100);
		}
		System.out.println(String.format("     -=- Case %02d :: No assertions", i));
	}

	// 21) Execution control: check when functions may be susceptible to MiTM attacks
	/*
	 * $connection = ssh2_connect("scanme.nmap.org", 22, array("hostkey"=>"ssh-rsa")); try {
	 * if(!ssh2_auth_pubkey_file($connection, "username", "/etc/hosts", "/etc/hosts", "secret")) {
	 * $defense->attackDetected("Authenticity check failed", 100); } } catch (Exception $e) {
	 * $defense->attackDetected("Authenticity check failed", 100); }
	 */

	// 22) Execution control: check if the canonical path differs from the path entered by the user (path traversal
	// attack)
	@Test
	public void canonicalPathDiffersFromAbsolute_ShouldLogAttack() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		MockHttpServletRequest request = getBaseRequestForTest();
		String path = "/somedir/.././somefile";
		request.setParameter("path", path);
		defense.checkPath(request, path);
		System.out.println(String.format("     -=- Case %02d :: No assertions", i));
	}

	// 23) Execution control: check if the anti Cross-Site Request Forgery (CSRF) token differs from the original
	// if(!verifyAntiXSRF(anti-xsrf-token))
	@Test
	public void invalidAntiXSRFToken_ShouldLogAttack() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		MockHttpServletRequest request = getBaseRequestForTest();
		// if (!verifyAntiXSRF(anti-xsrf-token))
		defense.attackDetected(request, "Anti-XSRF token invalid", 100);
		System.out.println(String.format("     -=- Case %02d :: No assertions", i));
	}

	// 24) Execution control: check if the origin is forbidden for the user's session
	@Test
	public void forbiddenOrigin_ShouldLogAttack() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		MockHttpServletRequest request = getBaseRequestForTest();
		// if (!isGeoLocationForbidden(request.getSession()))
		defense.attackDetected(request, "Geo location is forbidden", 100);
		System.out.println(String.format("     -=- Case %02d :: No assertions", i));
	}

	// 25) if (login($user, $pass) && )
	@Test
	public void outOfBusinessHours_ShouldAlertAdmin() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		Calendar now = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
		int hour = now.get(Calendar.HOUR_OF_DAY);
		if (hour < 8 || hour > 20) {
			defense.alertAdmin("The user logged in outside business hours");
		}
		System.out.println(String.format("     -=- Case %02d :: No assertions", i));
	}

	// 26) Execution control: check if the user triggered an unexpected catch statement
	@Test
	public void unexpectedCatchException_ShouldLogAttack() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		MockHttpServletRequest request = getBaseRequestForTest();
		request.addParameter("invert", "0");
		try {
			Double invert = Double.valueOf(request.getParameter("invert"));
			if (0.0 == invert) {
				throw new ArithmeticException("Attempted division by zero");
			}
			// dead code... is ilustrative
			double d = 1.0 / invert;
			System.out.println(d);
		} catch (Exception e) {
			defense.attackDetected(request, "Exception divided by zero should never happen", 20);
		}
		System.out.println(String.format("     -=- Case %02d :: No assertions", i));
	}

	// 27) Execution control: check if there are any uncaught exceptions
	// throw new Exception("this is an uncaught exception");

	// 28) Execution control: check if they are looping through passwords
	@Test
	public void passwordLoop_ShouldLogAttack() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		MockHttpServletRequest request = getBaseRequestForTest();
		request.setParameter("user", "user");
		request.setParameter("pass", "pass");

		// String user = request.getParameter("user");
		// String pass = request.getParameter("pass");
		// if (!login(user, pass)) {
		defense.attackDetected(request, "Password attempt", 10);
		System.out.println(String.format("     -=- Case %02d :: No assertions", i));
	}

	// 29) Execution control: check how fast they are
	@Test
	public void checkSpeed_ShouldReturnOk() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		MockHttpServletRequest request = getBaseRequestForTest();
		int result = defense.checkSpeed(request);
		Assert.assertEquals(Defense.OK, result, String.format("     -=- Case %02d :: FAILURE: Speed check should've returned OK.", i));
		System.out.println(String.format("     -=- Case %02d :: SUCCESS: Speed check analysis result OK.", i));
	}

	@Test
	public void checkSpeed_ShouldReturnAttack() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		MockHttpServletRequest request = getBaseRequestForTest();

		HttpSession session = request.getSession();
		session.setAttribute("requests_last_minute", new Date());
		session.setAttribute("amount_requests_last_minute", 99);

		defense.checkSpeed(request);
		int result = defense.checkSpeed(request);
		Assert.assertEquals(Defense.ATTACK, result, String.format("     -=- Case %02d :: FAILURE: Speed check should've returned ATTACK.", i));
		System.out.println(String.format("     -=- Case %02d :: SUCCESS: Speed check analysis result ATTACK.", i));
	}

	// 30.1) Post-execution control: check if the fake secret admin acccount has been leaked
	@Test
	public void checkFakeSecretAdminAccountLeakage_ShouldReturnAttack() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		MockHttpServletRequest request = getBaseRequestForTest();
		String responseBody = "0,secrethiddenadminaccount,1...";
		int result = defense.checkFakeSecretAdminAccountLeakage(request, responseBody);
		Assert.assertEquals(Defense.ATTACK, result, String.format("     -=- Case %02d :: FAILURE: secret admin account leakage should've returned ATTACK.", i));
		System.out.println(String.format("     -=- Case %02d :: SUCCESS: secret admin account leakage returned ATTACK.", i));
	}

	// 30.2) Post-execution control: check if the fake secret directory has been leaked
	@Test
	public void checkFakeSecretHiddenDirectoryLeakage_ShouldReturnAttack() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		MockHttpServletRequest request = getBaseRequestForTest();
		String responseBody = "/var/www/html/secrethiddendirectory";
		int result = defense.checkFakeSecretHiddenDirectoryLeakage(request, responseBody);
		Assert.assertEquals(Defense.ATTACK, result,
			String.format("     -=- Case %02d :: FAILURE: secret hidden directory leakage should've returned ATTACK.", i));
		System.out.println(String.format("     -=- Case %02d :: SUCCESS: secret hidden directory leakage returned ATTACK.", i));
	}

	// 31) Post-execution control: check if the request took too much time
	@Test
	public void executionTime_ShouldLogAttack() {
		int i = count++;
		System.out.println(String.format("  -=- Case %02d...", i));
		MockHttpServletRequest request = getBaseRequestForTest();
		Calendar c = new GregorianCalendar();
		c.add(Calendar.SECOND, -30);
		int result = defense.checkExecutionTime(request, c.getTime());
		Assert.assertEquals(Defense.ATTACK, result, String.format("     -=- Case %02d :: FAILURE: Execution time check should've returned ATTACK.", i));
		System.out.println(String.format("     -=- Case %02d :: SUCCESS: Execution time check returned ATTACK.", i));
	}

}