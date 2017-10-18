package com.ioactive.defense.persistence;

import static com.ioactive.defense.persistence.SQLiteDefensePersistence.SQLITE_DB_NAME;
import static org.testng.Assert.assertTrue;

import java.io.File;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.BeforeClass;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.Test;
import org.testng.collections.CollectionUtils;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;

@Test(enabled = false)
public class SQLiteDefensePersistenceTest {

	private static final String EOL = System.getProperty("line.separator");

	private final SQLiteDefensePersistence target = new SQLiteDefensePersistence();

	private final File db = new File(SQLITE_DB_NAME);
	private final File dbBackup = new File(String.format("%s.bkp", SQLITE_DB_NAME));

	@BeforeClass
	public void prepareBefore() {
		if (db.exists()) {
			db.renameTo(dbBackup);
		}
	}

	@AfterClass
	public void cleanUpAfter() {
		if (dbBackup.exists()) {
			dbBackup.renameTo(db);
		}
	}

	public void testGetAcceptedMethods() {
		List<String> expected = Lists.newArrayList("HEAD", "GET", "POST", "OPTIONS");
		List<String> actual = target.getAcceptedMethods();
		Set<String> union = Sets.newHashSet(expected);
		union.addAll(actual);

		Assert.assertEquals(expected.size(), union.size(),
			String.format("Accepted methods do not match:%s\t<expected: %s>%s\t<actual: %s>", EOL, expected, EOL, actual));
		union.removeAll(actual);
		Assert.assertFalse(CollectionUtils.hasElements(union));
	}

	public void testLogAttack() {
		String attack = "TEST";
		int score = 100;
		String user = "test-user";

		Map<String, Object> args = Maps.newLinkedHashMapWithExpectedSize(10);
		args.put("timestamp", new Date());
		args.put("application", "test-defense");
		args.put("ip", "0.0.0.0");
		args.put("user", user);
		args.put("cookie", "cookie");
		args.put("uri", "localhost:8888/test-defense");
		args.put("parameter", "{}");
		args.put("attack", attack);
		args.put("score", score);

		target.logAttack(args);

		assertTrue(target.isAttacker(user));
	}
}
