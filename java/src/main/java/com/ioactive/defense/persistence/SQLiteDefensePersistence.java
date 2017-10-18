package com.ioactive.defense.persistence;

import java.io.File;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.commons.lang3.StringUtils;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.ioactive.defense.exception.DBAccessException;

public class SQLiteDefensePersistence
	implements DefensePersistenceInterface {

	public static final String SQLITE_CONNECTION_STRING = "jdbc:sqlite:%s";
	public static final String SQLITE_DB_NAME = "attackers.db";
	public static final String SQLITE_JDBC_CLASSNAME = "org.sqlite.JDBC";

	private static final List<String> DB_INIT_STATEMENTS = ImmutableList
		.<String> builder()

		.add(
			"CREATE TABLE attacker (id INTEGER PRIMARY KEY, timestamp TEXT, application TEXT, ip TEXT, user TEXT, cookie TEXT, filename TEXT, uri TEXT, parameter TEXT, attack TEXT, score INTEGER)")
		.add("CREATE TABLE denyUserAgent (id INTEGER PRIMARY KEY, useragent TEXT)")
		.add(
			"INSERT INTO denyUserAgent (useragent) VALUES ('burpcollaborator'), ('dirbuster'), ('nessus'), ('nikto'), ('nmap'), ('paros'), ('python-urllib'), ('qualysguard'), ('sqlmap'), ('useragent'), ('w3af')")
		.add("CREATE TABLE denyUrlString (id INTEGER PRIMARY KEY, string TEXT)")
		.add("INSERT INTO denyUrlString (string) VALUES ('acunetix'), ('burpcollab'), ('nessus'), ('nikto'), ('parosproxy'), ('qualys'), ('vega'), ('ZAP')")
		.add("CREATE TABLE acceptHttpMethod (id INTEGER PRIMARY KEY, method TEXT)")
		.add("INSERT INTO acceptHttpMethod (method) VALUES ('HEAD'), ('GET'), ('POST'), ('OPTIONS')")
		.add("CREATE TABLE denyExtension (id INTEGER PRIMARY KEY, extension TEXT)")
		.add(
			"INSERT INTO denyExtension (extension) VALUES ('bac'), ('BAC'), ('backup'), ('BACKUP'), ('bak'), ('BAK'), ('conf'), ('cs'), ('csproj'), ('inc'), ('INC'), ('ini'), ('java'), ('log'), ('lst'), ('old'), ('OLD'), ('orig'), ('ORIG'), ('sav'), ('save'), ('temp'), ('tmp'), ('TMP'), ('vb'), ('vbproj')")

		.build();

	private static final String METHOD_COLNAME = "method";
	private static final String SELECT_METHODS_QUERY = String.format("SELECT %s FROM acceptHttpMethod", METHOD_COLNAME);
	private static final String SELECT_METHODS_FAIL_MSG = "Could not retrieve accepted http methods from DB.";

	private static final String DENY_URLS_COLNAME = "string";
	private static final String SELECT_DENY_URLS_QUERY = String.format("SELECT %s FROM denyUrlString", DENY_URLS_COLNAME);
	private static final String SELECT_DENY_URLS_FAIL_MSG = "Could not retrieve DeniedURLs from DB.";

	private static final String SELECT_DENY_USER_AGENTS_QUERY = "SELECT useragent FROM denyUserAgent";
	private static final String SELECT_DENY_USER_AGENTS_FAIL_MSG = "Could not retrieve Denied User agents from DB.";

	private static final String LOGGING_NOT_POSSIBLE_MSG = "Logging attack was not possible due to an error accessing the database.";
	private static final String CONNECTION_NOT_TERMINATED_MSG = "Connection to the DB could not be terminated due to an exception. This may cause memory leakage.";

	private static final String SELECT_ATTACKERS = "SELECT * FROM attacker";
	private static final String SELECT_ATTACKERS_FAIL_MSG = "Could not retrieve attackers from DB.";

	private static final String SELECT_ATTACKER_USER = "SELECT * FROM attacker where user = ?";
	private static final String SELECT_ATTACKER_FAIL_MSG = "Could not retrieve attackers from DB.";

	// Consider using spring's NamedParameterJDBCStatements
	private static final String[] QUERY_ARGUMENTS = new String[] { ":timestamp", ":application", ":ip", ":user", ":cookie", ":filename", ":uri", ":parameter",
		":attack", ":score" };
	private static final String[] ATTACKERS_COLUMN_NAMES = new String[] { "id", "timestamp", "application", "ip", "user", "cookie", "filename", "uri",
		"parameter", "attack", "score" };
	private final String INSERT_QUERY = "INSERT INTO attacker (timestamp, application, ip, user, cookie, filename, uri, parameter, attack, score) "
		+ "VALUES (" + StringUtils.join(QUERY_ARGUMENTS, ", ") + ")".replaceAll(":[^,)]+", "?,");

	private void initDB(Connection c) throws SQLException {
		Statement stmt = c.createStatement();
		for (String sql : DB_INIT_STATEMENTS) {
			stmt.executeUpdate(sql);
		}
	}

	private Connection getDBConnection() {
		boolean doInit = false;
		if (!new File(SQLITE_DB_NAME).exists()) {
			doInit = true;
		}
		Connection c = null;
		try {
			Class.forName(SQLITE_JDBC_CLASSNAME);
			c = DriverManager.getConnection(String.format(SQLITE_CONNECTION_STRING, SQLITE_DB_NAME));
			if (doInit) {
				initDB(c);
				System.out.println("No database was found and was initialized with default values.");
			}
			System.out.println("Opened database successfully.");
			return c;
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		} catch (SQLException e) {
			e.printStackTrace();
		}
		System.out.println("Cannot open database for usage.");
		return null;
	}

	// -------------------------- Interface methods --------------------------
	@Override
	public List<String> getAcceptedMethods() {
		// "SELECT method FROM acceptHttpMethod"
		Connection connection = getDBConnection();
		try {
			Statement stmt = connection.createStatement();
			ResultSet rs = stmt.executeQuery(SELECT_METHODS_QUERY);
			List<String> urls = Lists.newLinkedList();
			while (rs.next()) {
				urls.add(rs.getString(METHOD_COLNAME));
			}
			rs.close();
			stmt.close();
			return urls;
		} catch (SQLException e) {
			throw new DBAccessException(SELECT_METHODS_FAIL_MSG, e);
		} finally {
			try {
				connection.close();
			} catch (SQLException e) {
				throw new DBAccessException(CONNECTION_NOT_TERMINATED_MSG, e);
			}
		}
	}

	@Override
	public List<String> getDenyURLs() {
		// "SELECT string FROM denyUrlString"
		Connection connection = getDBConnection();
		try {
			Statement stmt = connection.createStatement();
			ResultSet rs = stmt.executeQuery(SELECT_DENY_URLS_QUERY);
			List<String> urls = Lists.newLinkedList();
			while (rs.next()) {
				urls.add(rs.getString("string"));
			}
			rs.close();
			stmt.close();
			return urls;
		} catch (SQLException e) {
			throw new DBAccessException(SELECT_DENY_URLS_FAIL_MSG, e);
		} finally {
			try {
				connection.close();
			} catch (SQLException e) {
				throw new DBAccessException(CONNECTION_NOT_TERMINATED_MSG, e);
			}
		}
	}

	@Override
	public void logAttack(Map<String, Object> args) {
		Connection connection = getDBConnection();
		PreparedStatement stmt = null;
		try {
			stmt = connection.prepareStatement(INSERT_QUERY);
			int i = 1;
			for (Entry<String, Object> entry : args.entrySet()) {
				stmt.setObject(i++, entry.getValue());
			}
			stmt.executeUpdate();
			stmt.close();
			System.out.println("Attack log complete whith arguments: " + args);

		} catch (SQLException e) {
			throw new DBAccessException(LOGGING_NOT_POSSIBLE_MSG, e);
		} finally {
			try {
				connection.close();
			} catch (SQLException e) {
				throw new DBAccessException(CONNECTION_NOT_TERMINATED_MSG, e);
			}
		}
	}

	@Override
	public List<String> getDeniedUserAgents() {
		Connection connection = getDBConnection();
		try {
			PreparedStatement stmt = connection.prepareStatement(SELECT_DENY_USER_AGENTS_QUERY);

			ResultSet rs = stmt.executeQuery();
			List<String> deniedUserAgents = Lists.newLinkedList();
			while (rs.next()) {
				deniedUserAgents.add(rs.getString("useragent"));
			}
			rs.close();
			stmt.close();
			return deniedUserAgents;
		} catch (SQLException e) {
			throw new DBAccessException(SELECT_DENY_USER_AGENTS_FAIL_MSG, e);
		} finally {
			try {
				connection.close();
			} catch (SQLException e) {
				throw new DBAccessException(CONNECTION_NOT_TERMINATED_MSG, e);
			}
		}
	}

	@Override
	public boolean isAttacker(String user) {
		Connection connection = getDBConnection();
		try {
			PreparedStatement stmt = connection.prepareStatement(SELECT_ATTACKER_USER);
			stmt.setString(1, user);
			ResultSet rs = stmt.executeQuery();
			boolean hasResults = rs.next();
			rs.close();
			stmt.close();
			return hasResults;
		} catch (SQLException e) {
			throw new DBAccessException(SELECT_ATTACKER_FAIL_MSG, e);
		} finally {
			try {
				connection.close();
			} catch (SQLException e) {
				throw new DBAccessException(CONNECTION_NOT_TERMINATED_MSG, e);
			}
		}
	}

	@Override
	public List<Map<String, Object>> getAttackersList() {
		List<Map<String, Object>> resultSet = Lists.newArrayList();
		Connection connection = getDBConnection();
		try {
			PreparedStatement stmt = connection.prepareStatement(SELECT_ATTACKERS);
			ResultSet rs = stmt.executeQuery();
			while (rs.next()) {
				Map<String, Object> row = Maps.newLinkedHashMap();
				for (String colname : ATTACKERS_COLUMN_NAMES) {
					row.put(colname, rs.getString(colname));
				}
				resultSet.add(row);
			}
			rs.close();
			stmt.close();
			return resultSet;
		} catch (SQLException e) {
			throw new DBAccessException(SELECT_ATTACKERS_FAIL_MSG, e);
		} finally {
			try {
				connection.close();
			} catch (SQLException e) {
				throw new DBAccessException(CONNECTION_NOT_TERMINATED_MSG, e);
			}
		}
	}
}
