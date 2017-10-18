package com.ioactive.defense.util;

import static org.apache.commons.lang3.StringUtils.contains;
import static org.apache.commons.lang3.StringUtils.upperCase;

import java.util.List;
import java.util.Set;

import com.google.common.base.Function;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;

public class StringsListsUtils {

	private static Function<String, String> UPPERCASE_STRING = new Function<String, String>() {

		@Override
		public String apply(String input) {
			return upperCase(input);
		}
	};

	public static boolean containsIgnoreCase(List<String> haystack, String needle) {
		Set<String> upperCasedHaystack = Sets.newHashSet(Lists.transform(haystack, UPPERCASE_STRING));
		return upperCasedHaystack.contains(upperCase(needle));
	}

	public static boolean isContainedIgnoringCase(List<String> haystack, String needle) {
		String upperNeedle = upperCase(needle);
		for (String deniedUrl : haystack) {
			if (contains(upperNeedle, upperCase(deniedUrl))) {
				return true;
			}
		}
		return false;
	}

}
