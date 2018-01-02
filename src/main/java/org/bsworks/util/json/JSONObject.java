/*
 Copyright (c) 2002 JSON.org

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 The Software shall be used for Good, not Evil.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 SOFTWARE.
 */
package org.bsworks.util.json;

import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.Set;


/**
 * See http://www.json.org/java/.
 *
 * @author JSON.org
 * @author Lev Himmelfarb
 */
public class JSONObject {

	/**
	 * {@link JSONObject#NULL} is equivalent to the value that JavaScript calls
	 * null, whilst Java's null is equivalent to the value that JavaScript
	 * calls undefined.
	 */
	private static final class Null {

		/**
		 * Create.
		 */
		Null() {}

		/**
		 * There is only intended to be a single instance of the Null object,
		 * so the clone method returns itself.
		 *
		 * @return Null.
		 */
		@Override
		protected final Object clone() {

			return this;
		}

		/**
		 * A Null object is equal to the null value and to itself.
		 *
		 * @param object An object to test for nullness.
		 * @return {@code true} if the object parameter is the
		 * {@link JSONObject#NULL} object or {@code null}.
		 */
		@Override
		public boolean equals(final Object object) {

			return ((object == null) || (object == this));
		}

		/**
		 * Get the "null" string value.
		 *
		 * @return The string "null".
		 */
		@Override
		public String toString() {

			return "null";
		}

		/**
		 * Get hash code of the "null" string.
		 *
		 * @return Hash code of the string "null".
		 */
		@Override
		public int hashCode() {

			return "null".hashCode();
		}
	}

	/**
	 * The map where the JSON object's properties are kept.
	 */
	private final Map<String, Object> props = new HashMap<>();

	/**
	 * It is sometimes more convenient and less ambiguous to have a
	 * {@code NULL} object than to use Java's {@code null} value.
	 * {@code JSONObject.NULL.equals(null)} returns {@code true}.
	 * {@code JSONObject.NULL.toString()} returns "null".
	 */
	public static final Object NULL = new Null();


	/**
	 * Construct an empty JSON object.
	 */
	public JSONObject() {}

	/**
	 * Construct a JSON object from a tokenizer.
	 *
	 * @param parser A tokenizer containing the source JSON string.
	 * @throws JSONException If there is a syntax error in the source string or
	 * a duplicated key.
	 * @throws IOException If an I/O error happens reading from the tokenizer.
	 */
	public JSONObject(final JSONTokener parser)
		throws JSONException, IOException {

		// object opens with '{'
		if (parser.nextClean() != '{')
			throw new JSONException(parser, "A JSON object text must begin with '{'.");

		// read key/value pairs
		while (true) {

			// analyze initial pair character
			char c = parser.nextClean();
			if (c == '}')
				break;
			if (c == 0)
				throw new JSONException(parser, "A JSON object text must end with '}'.");

			// put it back
			parser.back();

			// read the pair's key
			final String key = parser.nextValue().toString();

			// the key is followed by ':'
			c = parser.nextClean();
			if (c != ':')
				throw new JSONException(parser, "Expected a ':' after a key.");

			// read the value and store the property
			this.putOnce(key, parser.nextValue());

			// pairs are separated by ','
			c = parser.nextClean();
			if (c == '}')
				break;
			if (c != ',')
				throw new JSONException(parser, "Expected a ',' or '}'.");
		}
	}

	/**
	 * Construct a JSON object from a map.
	 *
	 * @param props A map used to initialize the contents of the JSON object.
	 * Can be {@code null} to create an empty object. Map entries with
	 * {@code null} value are ignored.
	 */
	public JSONObject(final Map<String, Object> props) {

		if (props == null)
			return;

		for (final Map.Entry<String, Object> entry : props.entrySet()) {
			final Object value = entry.getValue();
			if (value != null)
				this.props.put(entry.getKey(), JSONObject.wrap(value));
		}
	}

	/**
	 * Construct a JSON object from an object using bean getters. It reflects
	 * on all of the public methods of the object. For each of the methods with
	 * no parameters and a name starting with "get" or "is" followed by an
	 * uppercase letter, the method is invoked and a key and the value returned
	 * are put into the new JSON object.
	 *
	 * <p>The key is formed by removing the "get" or "is" prefix. If the second
	 * remaining character is not upper case, then the first character is
	 * converted to lower case.
	 *
	 * <p>For example, if an object has a method named "getName" and if the
	 * result of calling {@code object.getName()} is "Larry Fine", then the
	 * JSON object will contain {@code "name": "Larry Fine"}.
	 *
	 * @param bean An object that has getter methods that should be used to
	 * make a JSON object.
	 */
	public JSONObject(final Object bean) {

		this.populateMap(bean);
	}

	/**
	 * Construct a JSON object from an object using reflection to find the
	 * public members. The resulting JSON object's keys will be the strings
	 * from the names array and the values will be the field values associated
	 * with those keys in the object. If a key is not found or not visible,
	 * then it will not be copied into the new JSON object.
	 *
	 * @param object An object that has fields that should be used to make a
	 * JSON object.
	 * @param names An array of strings, the names of the fields to be obtained
	 * from the object.
	 */
	public JSONObject(final Object object, final String names[]) {

		final Class<?> c = object.getClass();
		for (final String name : names) {
			try {
				this.putOpt(name, c.getField(name).get(object));
			} catch (@SuppressWarnings("unused") Exception e) {
				// skip the property
			}
		}
	}

	/**
	 * Construct a JSON object from a {@link ResourceBundle}.
	 *
	 * @param baseName The {@link ResourceBundle} base name.
	 * @param locale The {@link Locale} to load the {@link ResourceBundle} for.
	 */
	public JSONObject(final String baseName, final Locale locale) {

		final ResourceBundle bundle = ResourceBundle.getBundle(
				baseName, locale,
				Thread.currentThread().getContextClassLoader()
		);

		for (final Enumeration<String> keys = bundle.getKeys(); keys.hasMoreElements();) {
			final Object key = keys.nextElement();
			if (key != null) {

				// Go through the path, ensuring that there is a nested
				// JSONObject for each segment except the last. Add the value
				// using the last segment's name into the deepest nested
				// JSONObject.

				final String[] path = ((String) key).split("\\.");
				final int last = path.length - 1;
				JSONObject target = this;
				for (int i = 0; i < last; i++) {
					final String segment = path[i];
					JSONObject nextTarget = target.optJSONObject(segment);
					if (nextTarget == null) {
						nextTarget = new JSONObject();
						target.put(segment, nextTarget);
					}
					target = nextTarget;
				}
				target.put(path[last], bundle.getString((String) key));
			}
		}
	}

	/**
	 * Accumulate values under a key. It is similar to the put method except
	 * that if there is already an object stored under the key then a JSONArray
	 * is stored under the key to hold all of the accumulated values. If there
	 * is already a JSONArray, then the new value is appended to it. In
	 * contrast, the put method replaces the previous value.
	 *
	 * If only one value is accumulated that is not a JSONArray, then the result
	 * will be the same as using put. But if multiple values are accumulated,
	 * then the result will be like append.
	 *
	 * @param key
	 *			A key string.
	 * @param value
	 *			An object to be accumulated under the key.
	 * @return this.
	 */
	public JSONObject accumulate(String key, Object value) {
		testValidity(value);
		Object object = this.opt(key);
		if (object == null) {
			this.put(key,
					value instanceof JSONArray ? new JSONArray().put(value)
							: value);
		} else if (object instanceof JSONArray) {
			((JSONArray) object).put(value);
		} else {
			this.put(key, new JSONArray().put(object).put(value));
		}
		return this;
	}

	/**
	 * Append values to the array under a key. If the key does not exist in the
	 * JSONObject, then the key is put in the JSONObject with its value being a
	 * JSONArray containing the value parameter. If the key was already
	 * associated with a JSONArray, then the value parameter is appended to it.
	 *
	 * @param key
	 *			A key string.
	 * @param value
	 *			An object to be accumulated under the key.
	 * @return this.
	 */
	public JSONObject append(String key, Object value) {
		testValidity(value);
		Object object = this.opt(key);
		if (object == null) {
			this.put(key, new JSONArray().put(value));
		} else if (object instanceof JSONArray) {
			this.put(key, ((JSONArray) object).put(value));
		} else {
			throw new IllegalArgumentException("JSONObject[" + key
					+ "] is not a JSONArray.");
		}
		return this;
	}

	/**
	 * Produce a string from a double. The string "null" will be returned if the
	 * number is not finite.
	 *
	 * @param d
	 *			A double.
	 * @return A String.
	 */
	public static String doubleToString(double d) {
		if (Double.isInfinite(d) || Double.isNaN(d)) {
			return "null";
		}

// Shave off trailing zeros and decimal point, if possible.

		String string = Double.toString(d);
		if (string.indexOf('.') > 0 && string.indexOf('e') < 0
				&& string.indexOf('E') < 0) {
			while (string.endsWith("0")) {
				string = string.substring(0, string.length() - 1);
			}
			if (string.endsWith(".")) {
				string = string.substring(0, string.length() - 1);
			}
		}
		return string;
	}

	/**
	 * Get the value object associated with a key.
	 *
	 * @param key
	 *			A key string.
	 * @return The object associated with the key.
	 */
	public Object get(String key) {
		if (key == null) {
			throw new IllegalArgumentException("Null key.");
		}
		Object object = this.opt(key);
		if (object == null) {
			throw new IllegalArgumentException("JSONObject[" + quote(key) + "] not found.");
		}
		return object;
	}
	/**
	 * Get the value object associated with a key.
	 *
	 * @param key
	 *			A key string.
	 * @param defaultVal Default value.
	 * @return The object associated with the key.
	 */
	public Object get(String key, Object defaultVal) {
		if (key == null) {
			throw new IllegalArgumentException("Null key.");
		}
		Object object = this.opt(key);
		if (object == null) {
			return defaultVal;
		}
		return object;
	}

	/**
	 * Get the boolean value associated with a key.
	 *
	 * @param key
	 *			A key string.
	 * @return The truth.
	 * @throws IllegalArgumentException
	 *			 if the value is not a Boolean or the String "true" or
	 *			 "false".
	 */
	public boolean getBoolean(String key) {
		Object object = this.get(key);
		if (object.equals(Boolean.FALSE)
				|| (object instanceof String && ((String) object)
						.equalsIgnoreCase("false"))) {
			return false;
		} else if (object.equals(Boolean.TRUE)
				|| (object instanceof String && ((String) object)
						.equalsIgnoreCase("true"))) {
			return true;
		}
		throw new IllegalArgumentException("JSONObject[" + quote(key)
				+ "] is not a Boolean.");
	}

	/**
	 * Get the double value associated with a key.
	 *
	 * @param key
	 *			A key string.
	 * @return The numeric value.
	 * @throws IllegalArgumentException
	 *			 if the key is not found or if the value is not a Number
	 *			 object and cannot be converted to a number.
	 */
	public double getDouble(String key) {
		Object object = this.get(key);
		try {
			return object instanceof Number ? ((Number) object).doubleValue()
					: Double.parseDouble((String) object);
		} catch (@SuppressWarnings("unused") Exception e) {
			throw new IllegalArgumentException("JSONObject[" + quote(key)
					+ "] is not a number.");
		}
	}

	/**
	 * Get the int value associated with a key.
	 *
	 * @param key
	 *			A key string.
	 * @return The integer value.
	 * @throws IllegalArgumentException
	 *			 if the key is not found or if the value cannot be converted
	 *			 to an integer.
	 */
	public int getInt(String key) {
		Object object = this.get(key);
		try {
			return object instanceof Number ? ((Number) object).intValue()
					: Integer.parseInt((String) object);
		} catch (@SuppressWarnings("unused") Exception e) {
			throw new IllegalArgumentException("JSONObject[" + quote(key)
					+ "] is not an int.");
		}
	}

	/**
	 * Get the JSONArray value associated with a key.
	 *
	 * @param key
	 *			A key string.
	 * @return A JSONArray which is the value.
	 * @throws IllegalArgumentException
	 *			 if the key is not found or if the value is not a JSONArray.
	 */
	public JSONArray getJSONArray(String key) {
		Object object = this.get(key);
		if (object instanceof JSONArray) {
			return (JSONArray) object;
		}
		throw new IllegalArgumentException("JSONObject[" + quote(key)
				+ "] is not a JSONArray.");
	}

	/**
	 * Get the JSONObject value associated with a key.
	 *
	 * @param key
	 *			A key string.
	 * @return A JSONObject which is the value.
	 * @throws IllegalArgumentException
	 *			 if the key is not found or if the value is not a JSONObject.
	 */
	public JSONObject getJSONObject(String key) {
		Object object = this.get(key);
		if (object instanceof JSONObject) {
			return (JSONObject) object;
		}
		throw new IllegalArgumentException("JSONObject[" + quote(key)
				+ "] is not a JSONObject.");
	}

	/**
	 * Get the long value associated with a key.
	 *
	 * @param key
	 *			A key string.
	 * @return The long value.
	 * @throws IllegalArgumentException
	 *			 if the key is not found or if the value cannot be converted
	 *			 to a long.
	 */
	public long getLong(String key) {
		Object object = this.get(key);
		try {
			return object instanceof Number ? ((Number) object).longValue()
					: Long.parseLong((String) object);
		} catch (@SuppressWarnings("unused") Exception e) {
			throw new IllegalArgumentException("JSONObject[" + quote(key)
					+ "] is not a long.");
		}
	}

	/**
	 * Get an array of field names from a JSONObject.
	 * @param jo The object.
	 *
	 * @return An array of field names, or null if there are no names.
	 */
	public static String[] getNames(JSONObject jo) {
		int length = jo.length();
		if (length == 0) {
			return null;
		}
		Iterator<String> iterator = jo.keys();
		String[] names = new String[length];
		int i = 0;
		while (iterator.hasNext()) {
			names[i] = iterator.next();
			i += 1;
		}
		return names;
	}

	/**
	 * Get an array of field names from an Object.
	 * @param object The object.
	 *
	 * @return An array of field names, or null if there are no names.
	 */
	public static String[] getNames(Object object) {
		if (object == null) {
			return null;
		}
		Class<?> klass = object.getClass();
		Field[] fields = klass.getFields();
		int length = fields.length;
		if (length == 0) {
			return null;
		}
		String[] names = new String[length];
		for (int i = 0; i < length; i += 1) {
			names[i] = fields[i].getName();
		}
		return names;
	}

	/**
	 * Get the string associated with a key.
	 *
	 * @param key
	 *			A key string.
	 * @return A string which is the value.
	 * @throws IllegalArgumentException
	 *			 if there is no string value for the key.
	 */
	public String getString(String key) {
		Object object = this.get(key);
		if (object instanceof String) {
			return (String) object;
		}
		throw new IllegalArgumentException("JSONObject[" + quote(key) + "] not a string.");
	}
	/**
	 * Get the string associated with a key.
	 *
	 * @param key
	 *			A key string.
	 * @param defaultVal Default value.
	 * @return A string which is the value.
	 * @throws IllegalArgumentException
	 *			 if there is no string value for the key.
	 */
	public String getString(String key, String defaultVal) {
		Object object = this.get(key, defaultVal);
		if (object == null)
			return null;
		if (object instanceof String) {
			return (String) object;
		}
		throw new IllegalArgumentException("JSONObject[" + quote(key) + "] not a string.");
	}

	/**
	 * Determine if the JSONObject contains a specific key.
	 *
	 * @param key
	 *			A key string.
	 * @return true if the key exists in the JSONObject.
	 */
	public boolean has(String key) {
		return this.props.containsKey(key);
	}

	/**
	 * Increment a property of a JSONObject. If there is no such property,
	 * create one with a value of 1. If there is such a property, and if it is
	 * an Integer, Long, Double, or Float, then add one to it.
	 *
	 * @param key
	 *			A key string.
	 * @return this.
	 */
	public JSONObject increment(String key) {
		Object value = this.opt(key);
		if (value == null) {
			this.put(key, 1);
		} else if (value instanceof Integer) {
			this.put(key, ((Integer) value).intValue() + 1);
		} else if (value instanceof Long) {
			this.put(key, ((Long) value).longValue() + 1);
		} else if (value instanceof Double) {
			this.put(key, ((Double) value).doubleValue() + 1);
		} else if (value instanceof Float) {
			this.put(key, ((Float) value).floatValue() + 1);
		} else {
			throw new IllegalArgumentException("Unable to increment [" + quote(key) + "].");
		}
		return this;
	}

	/**
	 * Determine if the value associated with the key is null or if there is no
	 * value.
	 *
	 * @param key
	 *			A key string.
	 * @return true if there is no value associated with the key or if the value
	 *		 is the JSONObject.NULL object.
	 */
	public boolean isNull(String key) {
		return JSONObject.NULL.equals(this.opt(key));
	}

	/**
	 * Get an enumeration of the keys of the JSONObject.
	 *
	 * @return An iterator of the keys.
	 */
	public Iterator<String> keys() {
		return this.keySet().iterator();
	}

	/**
	 * Get a set of keys of the JSONObject.
	 *
	 * @return A keySet.
	 */
	public Set<String> keySet() {
		return this.props.keySet();
	}

	/**
	 * Get the number of keys stored in the JSONObject.
	 *
	 * @return The number of keys in the JSONObject.
	 */
	public int length() {
		return this.props.size();
	}

	/**
	 * Produce a JSONArray containing the names of the elements of this
	 * JSONObject.
	 *
	 * @return A JSONArray containing the key strings, or null if the JSONObject
	 *		 is empty.
	 */
	public JSONArray names() {
		JSONArray ja = new JSONArray();
		Iterator<String> keys = this.keys();
		while (keys.hasNext()) {
			ja.put(keys.next());
		}
		return ja.length() == 0 ? null : ja;
	}

	/**
	 * Produce a string from a Number.
	 *
	 * @param number
	 *			A Number
	 * @return A String.
	 */
	public static String numberToString(Number number) {
		if (number == null) {
			throw new IllegalArgumentException("Null pointer");
		}
		testValidity(number);

// Shave off trailing zeros and decimal point, if possible.

		String string = number.toString();
		if (string.indexOf('.') > 0 && string.indexOf('e') < 0
				&& string.indexOf('E') < 0) {
			while (string.endsWith("0")) {
				string = string.substring(0, string.length() - 1);
			}
			if (string.endsWith(".")) {
				string = string.substring(0, string.length() - 1);
			}
		}
		return string;
	}

	/**
	 * Get an optional value associated with a key.
	 *
	 * @param key
	 *			A key string.
	 * @return An object which is the value, or null if there is no value.
	 */
	public Object opt(String key) {
		return key == null ? null : this.props.get(key);
	}

	/**
	 * Get an optional boolean associated with a key. It returns false if there
	 * is no such key, or if the value is not Boolean.TRUE or the String "true".
	 *
	 * @param key
	 *			A key string.
	 * @return The truth.
	 */
	public boolean optBoolean(String key) {
		return this.optBoolean(key, false);
	}

	/**
	 * Get an optional boolean associated with a key. It returns the
	 * defaultValue if there is no such key, or if it is not a Boolean or the
	 * String "true" or "false" (case insensitive).
	 *
	 * @param key
	 *			A key string.
	 * @param defaultValue
	 *			The default.
	 * @return The truth.
	 */
	public boolean optBoolean(String key, boolean defaultValue) {
		try {
			return this.getBoolean(key);
		} catch (@SuppressWarnings("unused") Exception e) {
			return defaultValue;
		}
	}

	/**
	 * Get an optional double associated with a key, or NaN if there is no such
	 * key or if its value is not a number. If the value is a string, an attempt
	 * will be made to evaluate it as a number.
	 *
	 * @param key
	 *			A string which is the key.
	 * @return An object which is the value.
	 */
	public double optDouble(String key) {
		return this.optDouble(key, Double.NaN);
	}

	/**
	 * Get an optional double associated with a key, or the defaultValue if
	 * there is no such key or if its value is not a number. If the value is a
	 * string, an attempt will be made to evaluate it as a number.
	 *
	 * @param key
	 *			A key string.
	 * @param defaultValue
	 *			The default.
	 * @return An object which is the value.
	 */
	public double optDouble(String key, double defaultValue) {
		try {
			return this.getDouble(key);
		} catch (@SuppressWarnings("unused") Exception e) {
			return defaultValue;
		}
	}

	/**
	 * Get an optional int value associated with a key, or zero if there is no
	 * such key or if the value is not a number. If the value is a string, an
	 * attempt will be made to evaluate it as a number.
	 *
	 * @param key
	 *			A key string.
	 * @return An object which is the value.
	 */
	public int optInt(String key) {
		return this.optInt(key, 0);
	}

	/**
	 * Get an optional int value associated with a key, or the default if there
	 * is no such key or if the value is not a number. If the value is a string,
	 * an attempt will be made to evaluate it as a number.
	 *
	 * @param key
	 *			A key string.
	 * @param defaultValue
	 *			The default.
	 * @return An object which is the value.
	 */
	public int optInt(String key, int defaultValue) {
		try {
			return this.getInt(key);
		} catch (@SuppressWarnings("unused") Exception e) {
			return defaultValue;
		}
	}

	/**
	 * Get an optional JSONArray associated with a key. It returns null if there
	 * is no such key, or if its value is not a JSONArray.
	 *
	 * @param key
	 *			A key string.
	 * @return A JSONArray which is the value.
	 */
	public JSONArray optJSONArray(String key) {
		Object o = this.opt(key);
		return o instanceof JSONArray ? (JSONArray) o : null;
	}

	/**
	 * Get an optional JSONObject associated with a key. It returns null if
	 * there is no such key, or if its value is not a JSONObject.
	 *
	 * @param key
	 *			A key string.
	 * @return A JSONObject which is the value.
	 */
	public JSONObject optJSONObject(String key) {
		Object object = this.opt(key);
		return object instanceof JSONObject ? (JSONObject) object : null;
	}

	/**
	 * Get an optional long value associated with a key, or zero if there is no
	 * such key or if the value is not a number. If the value is a string, an
	 * attempt will be made to evaluate it as a number.
	 *
	 * @param key
	 *			A key string.
	 * @return An object which is the value.
	 */
	public long optLong(String key) {
		return this.optLong(key, 0);
	}

	/**
	 * Get an optional long value associated with a key, or the default if there
	 * is no such key or if the value is not a number. If the value is a string,
	 * an attempt will be made to evaluate it as a number.
	 *
	 * @param key
	 *			A key string.
	 * @param defaultValue
	 *			The default.
	 * @return An object which is the value.
	 */
	public long optLong(String key, long defaultValue) {
		try {
			return this.getLong(key);
		} catch (@SuppressWarnings("unused") Exception e) {
			return defaultValue;
		}
	}

	/**
	 * Get an optional string associated with a key. It returns an empty string
	 * if there is no such key. If the value is not a string and is not null,
	 * then it is converted to a string.
	 *
	 * @param key
	 *			A key string.
	 * @return A string which is the value.
	 */
	public String optString(String key) {
		return this.optString(key, "");
	}

	/**
	 * Get an optional string associated with a key. It returns the defaultValue
	 * if there is no such key.
	 *
	 * @param key
	 *			A key string.
	 * @param defaultValue
	 *			The default.
	 * @return A string which is the value.
	 */
	public String optString(String key, String defaultValue) {
		Object object = this.opt(key);
		return NULL.equals(object) ? defaultValue : object.toString();
	}

	/**
	 * @param bean The bean.
	 */
	private void populateMap(Object bean) {
		Class<?> klass = bean.getClass();

// If klass is a System class then set includeSuperClass to false.

		boolean includeSuperClass = klass.getClassLoader() != null;

		Method[] methods = includeSuperClass ? klass.getMethods() : klass
				.getDeclaredMethods();
		for (int i = 0; i < methods.length; i += 1) {
			try {
				Method method = methods[i];
				if (Modifier.isPublic(method.getModifiers())) {
					String name = method.getName();
					String key = "";
					if (name.startsWith("get")) {
						if ("getClass".equals(name)
								|| "getDeclaringClass".equals(name)) {
							key = "";
						} else {
							key = name.substring(3);
						}
					} else if (name.startsWith("is")) {
						key = name.substring(2);
					}
					if (key.length() > 0
							&& Character.isUpperCase(key.charAt(0))
							&& method.getParameterTypes().length == 0) {
						if (key.length() == 1) {
							key = key.toLowerCase();
						} else if (!Character.isUpperCase(key.charAt(1))) {
							key = key.substring(0, 1).toLowerCase()
									+ key.substring(1);
						}

						Object result = method.invoke(bean, (Object[]) null);
						if (result != null) {
							this.props.put(key, wrap(result));
						}
					}
				}
			} catch (@SuppressWarnings("unused") Exception ignore) {
				// nothing
			}
		}
	}

	/**
	 * Put a key/boolean pair in the JSONObject.
	 *
	 * @param key
	 *			A key string.
	 * @param value
	 *			A boolean which is the value.
	 * @return this.
	 */
	public JSONObject put(String key, boolean value) {
		this.put(key, value ? Boolean.TRUE : Boolean.FALSE);
		return this;
	}

	/**
	 * Put a key/value pair in the JSONObject, where the value will be a
	 * JSONArray which is produced from a Collection.
	 *
	 * @param key
	 *			A key string.
	 * @param value
	 *			A Collection value.
	 * @return this.
	 */
	public JSONObject put(String key, Collection<Object> value) {
		this.put(key, new JSONArray(value));
		return this;
	}

	/**
	 * Put a key/double pair in the JSONObject.
	 *
	 * @param key
	 *			A key string.
	 * @param value
	 *			A double which is the value.
	 * @return this.
	 */
	public JSONObject put(String key, double value) {
		this.put(key, new Double(value));
		return this;
	}

	/**
	 * Put a key/int pair in the JSONObject.
	 *
	 * @param key
	 *			A key string.
	 * @param value
	 *			An int which is the value.
	 * @return this.
	 */
	public JSONObject put(String key, int value) {
		this.put(key, new Integer(value));
		return this;
	}

	/**
	 * Put a key/long pair in the JSONObject.
	 *
	 * @param key
	 *			A key string.
	 * @param value
	 *			A long which is the value.
	 * @return this.
	 */
	public JSONObject put(String key, long value) {
		this.put(key, new Long(value));
		return this;
	}

	/**
	 * Put a key/value pair in the JSONObject, where the value will be a
	 * JSONObject which is produced from a Map.
	 *
	 * @param key
	 *			A key string.
	 * @param value
	 *			A Map value.
	 * @return this.
	 */
	public JSONObject put(String key, Map<String, Object> value) {
		this.put(key, new JSONObject(value));
		return this;
	}

	/**
	 * Put a key/value pair in the JSONObject. If the value is null, then the
	 * key will be removed from the JSONObject if it is present.
	 *
	 * @param key
	 *			A key string.
	 * @param value
	 *			An object which is the value. It should be of one of these
	 *			types: Boolean, Double, Integer, JSONArray, JSONObject, Long,
	 *			String, or the JSONObject.NULL object.
	 * @return this.
	 */
	public JSONObject put(String key, Object value) {
		if (key == null) {
			throw new NullPointerException("Null key.");
		}
		if (value != null) {
			testValidity(value);
			this.props.put(key, value);
		} else {
			this.remove(key);
		}
		return this;
	}

	/**
	 * Put a key/value pair in the JSONObject, but only if the key and the value
	 * are both non-null, and only if there is not already a member with that
	 * name.
	 *
	 * @param key string
	 * @param value object
	 * @return this.
	 */
	public JSONObject putOnce(String key, Object value) {
		if (key != null && value != null) {
			if (this.opt(key) != null) {
				throw new IllegalArgumentException("Duplicate key \"" + key + "\"");
			}
			this.put(key, value);
		}
		return this;
	}

	/**
	 * Put a key/value pair in the JSONObject, but only if the key and the value
	 * are both non-null.
	 *
	 * @param key
	 *			A key string.
	 * @param value
	 *			An object which is the value. It should be of one of these
	 *			types: Boolean, Double, Integer, JSONArray, JSONObject, Long,
	 *			String, or the JSONObject.NULL object.
	 * @return this.
	 */
	public JSONObject putOpt(String key, Object value) {
		if (key != null && value != null) {
			this.put(key, value);
		}
		return this;
	}

	/**
	 * Produce a string in double quotes with backslash sequences in all the
	 * right places. A backslash will be inserted within &lt;/, producing &lt;\/,
	 * allowing JSON text to be delivered in HTML. In JSON text, a string cannot
	 * contain a control character or an unescaped quote or backslash.
	 *
	 * @param string
	 *			A String
	 * @return A String correctly formatted for insertion in a JSON text.
	 */
	public static String quote(String string) {
		StringWriter sw = new StringWriter();
		synchronized (sw.getBuffer()) {
			try {
				return quote(string, sw).toString();
			} catch (@SuppressWarnings("unused") IOException ignored) {
				// will never happen - we are writing to a string writer
				return "";
			}
		}
	}

	/**
	 * @param string String
	 * @param w Writer
	 * @return Writer
	 * @throws IOException If error
	 */
	public static Writer quote(String string, Writer w) throws IOException {
		if (string == null || string.length() == 0) {
			w.write("\"\"");
			return w;
		}

		char b;
		char c = 0;
		String hhhh;
		int i;
		int len = string.length();

		w.write('"');
		for (i = 0; i < len; i += 1) {
			b = c;
			c = string.charAt(i);
			switch (c) {
			case '\\':
			case '"':
				w.write('\\');
				w.write(c);
				break;
			case '/':
				if (b == '<') {
					w.write('\\');
				}
				w.write(c);
				break;
			case '\b':
				w.write("\\b");
				break;
			case '\t':
				w.write("\\t");
				break;
			case '\n':
				w.write("\\n");
				break;
			case '\f':
				w.write("\\f");
				break;
			case '\r':
				w.write("\\r");
				break;
			default:
				if (c < ' ' || (c >= '\u0080' && c < '\u00a0')
						|| (c >= '\u2000' && c < '\u2100')) {
					w.write("\\u");
					hhhh = Integer.toHexString(c);
					w.write("0000", 0, 4 - hhhh.length());
					w.write(hhhh);
				} else {
					w.write(c);
				}
			}
		}
		w.write('"');
		return w;
	}

	/**
	 * Remove a name and its value, if present.
	 *
	 * @param key
	 *			The name to be removed.
	 * @return The value that was associated with the name, or null if there was
	 *		 no value.
	 */
	public Object remove(String key) {
		return this.props.remove(key);
	}

	/**
	 * Determine if two JSONObjects are similar.
	 * They must contain the same set of names which must be associated with
	 * similar values.
	 *
	 * @param other The other JSONObject
	 * @return true if they are equal
	 */
	public boolean similar(Object other) {
		try {
			if (!(other instanceof JSONObject)) {
				return false;
			}
			Set<String> set = this.keySet();
			if (!set.equals(((JSONObject)other).keySet())) {
				return false;
			}
			Iterator<String> iterator = set.iterator();
			while (iterator.hasNext()) {
				String name = iterator.next();
				Object valueThis = this.get(name);
				Object valueOther = ((JSONObject)other).get(name);
				if (valueThis instanceof JSONObject) {
					if (!((JSONObject)valueThis).similar(valueOther)) {
						return false;
					}
				} else if (valueThis instanceof JSONArray) {
					if (!((JSONArray)valueThis).similar(valueOther)) {
						return false;
					}
				} else if (!valueThis.equals(valueOther)) {
					return false;
				}
			}
			return true;
		} catch (@SuppressWarnings("unused") Throwable exception) {
			return false;
		}
	}

	/**
	 * Try to convert a string into a number, boolean, or null. If the string
	 * can't be converted, return the string.
	 *
	 * @param string
	 *			A String.
	 * @return A simple JSON value.
	 */
	public static Object stringToValue(String string) {
		Double d;
		if (string.equals("")) {
			return string;
		}
		if (string.equalsIgnoreCase("true")) {
			return Boolean.TRUE;
		}
		if (string.equalsIgnoreCase("false")) {
			return Boolean.FALSE;
		}
		if (string.equalsIgnoreCase("null")) {
			return JSONObject.NULL;
		}

		/*
		 * If it might be a number, try converting it. If a number cannot be
		 * produced, then the value will just be a string.
		 */

		char b = string.charAt(0);
		if ((b >= '0' && b <= '9') || b == '-') {
			try {
				if (string.indexOf('.') > -1 || string.indexOf('e') > -1
						|| string.indexOf('E') > -1) {
					d = Double.valueOf(string);
					if (!d.isInfinite() && !d.isNaN()) {
						return d;
					}
				} else {
					Long myLong = new Long(string);
					if (string.equals(myLong.toString())) {
						if (myLong.intValue() == myLong.intValue()) {
							return Integer.valueOf(myLong.intValue());
						}
						return myLong;
					}
				}
			} catch (@SuppressWarnings("unused") Exception ignore) {
				// nothing
			}
		}
		return string;
	}

	/**
	 * Throw an exception if the object is a NaN or infinite number.
	 *
	 * @param o
	 *			The object to test.
	 */
	public static void testValidity(Object o) {
		if (o != null) {
			if (o instanceof Double) {
				if (((Double) o).isInfinite() || ((Double) o).isNaN()) {
					throw new IllegalArgumentException(
							"JSON does not allow non-finite numbers.");
				}
			} else if (o instanceof Float) {
				if (((Float) o).isInfinite() || ((Float) o).isNaN()) {
					throw new IllegalArgumentException(
							"JSON does not allow non-finite numbers.");
				}
			}
		}
	}

	/**
	 * Produce a JSONArray containing the values of the members of this
	 * JSONObject.
	 *
	 * @param names
	 *			A JSONArray containing a list of key strings. This determines
	 *			the sequence of the values in the result.
	 * @return A JSONArray of values.
	 */
	public JSONArray toJSONArray(JSONArray names) {
		if (names == null || names.length() == 0) {
			return null;
		}
		JSONArray ja = new JSONArray();
		for (int i = 0; i < names.length(); i += 1) {
			ja.put(this.opt(names.getString(i)));
		}
		return ja;
	}

	/**
	 * Make a JSON text of this JSONObject. For compactness, no whitespace is
	 * added. If this would not result in a syntactically correct JSON text,
	 * then null will be returned instead.
	 * <p>
	 * Warning: This method assumes that the data structure is acyclical.
	 *
	 * @return a printable, displayable, portable, transmittable representation
	 *		 of the object, beginning with <code>{</code>&nbsp;<small>(left
	 *		 brace)</small> and ending with <code>}</code>&nbsp;<small>(right
	 *		 brace)</small>.
	 */
	@Override
	public String toString() {
		try {
			return this.toString(0);
		} catch (@SuppressWarnings("unused") Exception e) {
			return null;
		}
	}

	/**
	 * Make a prettyprinted JSON text of this JSONObject.
	 * <p>
	 * Warning: This method assumes that the data structure is acyclical.
	 *
	 * @param indentFactor
	 *			The number of spaces to add to each level of indentation.
	 * @return a printable, displayable, portable, transmittable representation
	 *		 of the object, beginning with <code>{</code>&nbsp;<small>(left
	 *		 brace)</small> and ending with <code>}</code>&nbsp;<small>(right
	 *		 brace)</small>.
	 * @throws JSONException
	 *			 If the object contains an invalid number.
	 */
	public String toString(int indentFactor) throws JSONException {
		StringWriter w = new StringWriter();
		synchronized (w.getBuffer()) {
			return this.write(w, indentFactor, 0).toString();
		}
	}

	/**
	 * Make a JSON text of an Object value. If the object has an
	 * value.toJSONString() method, then that method will be used to produce the
	 * JSON text. The method is required to produce a strictly conforming text.
	 * If the object does not contain a toJSONString method (which is the most
	 * common case), then a text will be produced by other means. If the value
	 * is an array or Collection, then a JSONArray will be made from it and its
	 * toJSONString method will be called. If the value is a MAP, then a
	 * JSONObject will be made from it and its toJSONString method will be
	 * called. Otherwise, the value's toString method will be called, and the
	 * result will be quoted.
	 *
	 * <p>
	 * Warning: This method assumes that the data structure is acyclical.
	 *
	 * @param value
	 *			The value to be serialized.
	 * @return a printable, displayable, transmittable representation of the
	 *		 object, beginning with <code>{</code>&nbsp;<small>(left
	 *		 brace)</small> and ending with <code>}</code>&nbsp;<small>(right
	 *		 brace)</small>.
	 */
	@SuppressWarnings("unchecked")
	public static String valueToString(Object value) {
		if (value == null || value.equals(null)) {
			return "null";
		}
		if (value instanceof Number) {
			return numberToString((Number) value);
		}
		if (value instanceof Boolean || value instanceof JSONObject
				|| value instanceof JSONArray) {
			return value.toString();
		}
		if (value instanceof Map) {
			return new JSONObject((Map<String, Object>)value).toString();
		}
		if (value instanceof Collection) {
			return new JSONArray((Collection<Object>) value).toString();
		}
		if (value.getClass().isArray()) {
			return new JSONArray(value).toString();
		}
		return quote(value.toString());
	}

	/**
	 * Wrap an object, if necessary. If the object is null, return the NULL
	 * object. If it is an array or collection, wrap it in a JSONArray. If it is
	 * a map, wrap it in a JSONObject. If it is a standard property (Double,
	 * String, et al) then it is already wrapped. Otherwise, if it comes from
	 * one of the java packages, turn it into a string. And if it doesn't, try
	 * to wrap it in a JSONObject. If the wrapping fails, then null is returned.
	 *
	 * @param object
	 *			The object to wrap
	 * @return The wrapped value
	 */
	@SuppressWarnings("unchecked")
	public static Object wrap(Object object) {
		try {
			if (object == null) {
				return NULL;
			}
			if (object instanceof JSONObject || object instanceof JSONArray
					|| NULL.equals(object)
					|| object instanceof Byte || object instanceof Character
					|| object instanceof Short || object instanceof Integer
					|| object instanceof Long || object instanceof Boolean
					|| object instanceof Float || object instanceof Double
					|| object instanceof String) {
				return object;
			}

			if (object instanceof Collection) {
				return new JSONArray((Collection<Object>) object);
			}
			if (object.getClass().isArray()) {
				return new JSONArray(object);
			}
			if (object instanceof Map) {
				return new JSONObject((Map<String, Object>) object);
			}
			Package objectPackage = object.getClass().getPackage();
			String objectPackageName = objectPackage != null ? objectPackage
					.getName() : "";
			if (objectPackageName.startsWith("java.")
					|| objectPackageName.startsWith("javax.")
					|| object.getClass().getClassLoader() == null) {
				return object.toString();
			}
			return new JSONObject(object);
		} catch (@SuppressWarnings("unused") Exception exception) {
			return null;
		}
	}

	/**
	 * Write the contents of the JSONObject as JSON text to a writer. For
	 * compactness, no whitespace is added.
	 * <p>
	 * Warning: This method assumes that the data structure is acyclical.
	 * @param writer Writer
	 *
	 * @return The writer.
	 * @throws JSONException Error
	 */
	public Writer write(Writer writer) throws JSONException {
		return this.write(writer, 0, 0);
	}

	/**
	 * @param writer Writer
	 * @param value Value
	 * @param indentFactor Indent factor
	 * @param indent Indent
	 * @return Writer
	 * @throws JSONException Error
	 * @throws IOException Error
	 */
	@SuppressWarnings("unchecked")
	static final Writer writeValue(Writer writer, Object value,
			int indentFactor, int indent) throws JSONException, IOException {
		if (value == null || value.equals(null)) {
			writer.write("null");
		} else if (value instanceof JSONObject) {
			((JSONObject) value).write(writer, indentFactor, indent);
		} else if (value instanceof JSONArray) {
			((JSONArray) value).write(writer, indentFactor, indent);
		} else if (value instanceof Map) {
			new JSONObject((Map<String, Object>) value).write(writer, indentFactor, indent);
		} else if (value instanceof Collection) {
			new JSONArray((Collection<Object>) value).write(writer, indentFactor,
					indent);
		} else if (value.getClass().isArray()) {
			new JSONArray(value).write(writer, indentFactor, indent);
		} else if (value instanceof Number) {
			writer.write(numberToString((Number) value));
		} else if (value instanceof Boolean) {
			writer.write(value.toString());
		} else {
			quote(value.toString(), writer);
		}
		return writer;
	}

	/**
	 * @param writer Writer
	 * @param indent Indent
	 * @throws IOException Error
	 */
	static final void indent(Writer writer, int indent) throws IOException {
		for (int i = 0; i < indent; i += 1) {
			writer.write(' ');
		}
	}

	/**
	 * Write the contents of the JSONObject as JSON text to a writer. For
	 * compactness, no whitespace is added.
	 * <p>
	 * Warning: This method assumes that the data structure is acyclical.
	 *
	 * @param writer Writer
	 * @param indentFactor Indent factor
	 * @param indent Indent
	 * @return The writer.
	 * @throws JSONException Error
	 */
	Writer write(Writer writer, int indentFactor, int indent)
			throws JSONException {
		try {
			boolean commanate = false;
			final int length = this.length();
			Iterator<String> keys = this.keys();
			writer.write('{');

			if (length == 1) {
				Object key = keys.next();
				writer.write(quote(key.toString()));
				writer.write(':');
				if (indentFactor > 0) {
					writer.write(' ');
				}
				writeValue(writer, this.props.get(key), indentFactor, indent);
			} else if (length != 0) {
				final int newindent = indent + indentFactor;
				while (keys.hasNext()) {
					Object key = keys.next();
					if (commanate) {
						writer.write(',');
					}
					if (indentFactor > 0) {
						writer.write('\n');
					}
					indent(writer, newindent);
					writer.write(quote(key.toString()));
					writer.write(':');
					if (indentFactor > 0) {
						writer.write(' ');
					}
					writeValue(writer, this.props.get(key), indentFactor, newindent);
					commanate = true;
				}
				if (indentFactor > 0) {
					writer.write('\n');
				}
				indent(writer, indent);
			}
			writer.write('}');
			return writer;
		} catch (IOException exception) {
			throw new JSONException(exception);
		}
	}
}
