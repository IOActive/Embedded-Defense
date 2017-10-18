package com.ioactive.defense.util;

import java.util.Map;
import java.util.Map.Entry;

public class ParameterMapSerializer {

	public static String serializeParameterMap(Map<String, String[]> map) {
		StringBuilder serialization = new StringBuilder(256);
		serialization.append("{");
		for (Entry<String, String[]> parameterEntry : map.entrySet()) {
			String key = parameterEntry.getKey();
			String[] value = parameterEntry.getValue();
			serialization.append(String.format("%s: %s,", key, serializeStringArray(value)));
		}
		int i = serialization.lastIndexOf(",");
		if (i < 0) {
			serialization.append("}");
		} else {
			serialization.setCharAt(i, '}');
		}
		return serialization.toString();
	}

	public static String serializeStringArray(String[] array) {
		StringBuilder serialization = new StringBuilder(256);
		serialization.append("[");
		for (int i = 0; i < array.length; i++) {
			serialization.append(array[i]).append(", ");
		}
		int i = serialization.lastIndexOf(", ");
		if (i > 0) {
			int newLength = serialization.length() - 2;
			serialization.setLength(newLength);
		}
		serialization.append("]");
		return serialization.toString();
	}

}
