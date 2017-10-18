package com.ioactive.defense.persistence;

import java.util.List;
import java.util.Map;

public interface DefensePersistenceInterface {

	/**
	 * $results = $db->query("SELECT method FROM acceptHttpMethod");
	 * 
	 * @return
	 */
	List<String> getAcceptedMethods();

	List<String> getDenyURLs();

	List<String> getDeniedUserAgents();

	/**
	 * Log the attack into the database
	 * 
	 * @param sessionParameters
	 */
	void logAttack(Map<String, Object> sessionParameters);

	boolean isAttacker(String user);

	List<Map<String, Object>> getAttackersList();

}
