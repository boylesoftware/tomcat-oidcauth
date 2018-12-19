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
import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;


/**
 * See http://www.json.org/java/.
 *
 * @author JSON.org
 * @author Lev Himmelfarb
 */
public class JSONArray {

	/**
	 * The arrayList where the JSONArray's properties are kept.
	 */
	private final ArrayList<Object> myArrayList;

	/**
	 * Construct an empty JSONArray.
	 */
	public JSONArray() {
		this.myArrayList = new ArrayList<>();
	}

	/**
	 * Construct a JSONArray from a JSONTokener.
	 *
	 * @param x
	 *			A JSONTokener
	 * @throws JSONException
	 *			 If there is a syntax error.
	 * @throws IOException If error
	 */
	public JSONArray(JSONTokener x) throws JSONException, IOException {
		this();
		if (x.nextClean() != '[') {
			throw new JSONException(x, "A JSONArray text must start with '['");
		}
		if (x.nextClean() != ']') {
			x.back();
			for (;;) {
				if (x.nextClean() == ',') {
					x.back();
					this.myArrayList.add(JSONObject.NULL);
				} else {
					x.back();
					this.myArrayList.add(x.nextValue());
				}
				switch (x.nextClean()) {
				case ',':
					if (x.nextClean() == ']') {
						return;
					}
					x.back();
					break;
				case ']':
					return;
				default:
					throw new JSONException(x, "Expected a ',' or ']'");
				}
			}
		}
	}

	/**
	 * Construct a JSONArray from a Collection.
	 *
	 * @param collection
	 *			A Collection.
	 */
	public JSONArray(Collection<Object> collection) {
		this.myArrayList = new ArrayList<>();
		if (collection != null) {
			Iterator<Object> iter = collection.iterator();
			while (iter.hasNext()) {
				this.myArrayList.add(JSONObject.wrap(iter.next()));
			}
		}
	}

	/**
	 * Construct a JSONArray from an array
	 *
	 * @param array Array
	 */
	public JSONArray(Object array) {
		this();
		if (array.getClass().isArray()) {
			int length = Array.getLength(array);
			for (int i = 0; i < length; i += 1) {
				this.put(JSONObject.wrap(Array.get(array, i)));
			}
		} else {
			throw new IllegalArgumentException(
					"JSONArray initial value should be a string or collection or array.");
		}
	}

	/**
	 * Get the object value associated with an index.
	 *
	 * @param index
	 *			The index must be between 0 and length() - 1.
	 * @return An object value.
	 */
	public Object get(int index) {
		Object object = this.opt(index);
		if (object == null) {
			throw new IllegalArgumentException("JSONArray[" + index + "] not found.");
		}
		return object;
	}

	/**
	 * Get the boolean value associated with an index. The string values "true"
	 * and "false" are converted to boolean.
	 *
	 * @param index
	 *			The index must be between 0 and length() - 1.
	 * @return The truth.
	 */
	public boolean getBoolean(int index) {
		Object object = this.get(index);
		if (object.equals(Boolean.FALSE)
				|| (object instanceof String && ((String) object)
						.equalsIgnoreCase("false"))) {
			return false;
		} else if (object.equals(Boolean.TRUE)
				|| (object instanceof String && ((String) object)
						.equalsIgnoreCase("true"))) {
			return true;
		}
		throw new IllegalArgumentException("JSONArray[" + index + "] is not a boolean.");
	}

	/**
	 * Get the double value associated with an index.
	 *
	 * @param index
	 *			The index must be between 0 and length() - 1.
	 * @return The value.
	 */
	public double getDouble(int index) {
		Object object = this.get(index);
		try {
			return object instanceof Number ? ((Number) object).doubleValue()
					: Double.parseDouble((String) object);
		} catch (@SuppressWarnings("unused") Exception e) {
			throw new IllegalArgumentException("JSONArray[" + index + "] is not a number.");
		}
	}

	/**
	 * Get the int value associated with an index.
	 *
	 * @param index
	 *			The index must be between 0 and length() - 1.
	 * @return The value.
	 */
	public int getInt(int index) {
		Object object = this.get(index);
		try {
			return object instanceof Number ? ((Number) object).intValue()
					: Integer.parseInt((String) object);
		} catch (@SuppressWarnings("unused") Exception e) {
			throw new IllegalArgumentException("JSONArray[" + index + "] is not a number.");
		}
	}

	/**
	 * Get the JSONArray associated with an index.
	 *
	 * @param index
	 *			The index must be between 0 and length() - 1.
	 * @return A JSONArray value.
	 */
	public JSONArray getJSONArray(int index) {
		Object object = this.get(index);
		if (object instanceof JSONArray) {
			return (JSONArray) object;
		}
		throw new IllegalArgumentException("JSONArray[" + index + "] is not a JSONArray.");
	}

	/**
	 * Get the JSONObject associated with an index.
	 *
	 * @param index
	 *			subscript
	 * @return A JSONObject value.
	 */
	public JSONObject getJSONObject(int index) {
		Object object = this.get(index);
		if (object instanceof JSONObject) {
			return (JSONObject) object;
		}
		throw new IllegalArgumentException("JSONArray[" + index + "] is not a JSONObject.");
	}

	/**
	 * Get the long value associated with an index.
	 *
	 * @param index
	 *			The index must be between 0 and length() - 1.
	 * @return The value.
	 */
	public long getLong(int index) {
		Object object = this.get(index);
		try {
			return object instanceof Number ? ((Number) object).longValue()
					: Long.parseLong((String) object);
		} catch (@SuppressWarnings("unused") Exception e) {
			throw new IllegalArgumentException("JSONArray[" + index + "] is not a number.");
		}
	}

	/**
	 * Get the string associated with an index.
	 *
	 * @param index
	 *			The index must be between 0 and length() - 1.
	 * @return A string value.
	 */
	public String getString(int index) {
		Object object = this.get(index);
		if (object instanceof String) {
			return (String) object;
		}
		throw new IllegalArgumentException("JSONArray[" + index + "] not a string.");
	}

	/**
	 * Determine if the value is null.
	 *
	 * @param index
	 *			The index must be between 0 and length() - 1.
	 * @return true if the value at the index is null, or if there is no value.
	 */
	public boolean isNull(int index) {
		return JSONObject.NULL.equals(this.opt(index));
	}

	/**
	 * Make a string from the contents of this JSONArray. The
	 * <code>separator</code> string is inserted between each element. Warning:
	 * This method assumes that the data structure is acyclical.
	 *
	 * @param separator
	 *			A string that will be inserted between the elements.
	 * @return a string.
	 */
	public String join(String separator) {
		int len = this.length();
		StringBuilder sb = new StringBuilder();

		for (int i = 0; i < len; i += 1) {
			if (i > 0) {
				sb.append(separator);
			}
			sb.append(JSONObject.valueToString(this.myArrayList.get(i)));
		}
		return sb.toString();
	}

	/**
	 * Get the number of elements in the JSONArray, included nulls.
	 *
	 * @return The length (or size).
	 */
	public int length() {
		return this.myArrayList.size();
	}

	/**
	 * Get the optional object value associated with an index.
	 *
	 * @param index
	 *			The index must be between 0 and length() - 1.
	 * @return An object value, or null if there is no object at that index.
	 */
	public Object opt(int index) {
		return (index < 0 || index >= this.length()) ? null : this.myArrayList
				.get(index);
	}

	/**
	 * Get the optional boolean value associated with an index. It returns false
	 * if there is no value at that index, or if the value is not Boolean.TRUE
	 * or the String "true".
	 *
	 * @param index
	 *			The index must be between 0 and length() - 1.
	 * @return The truth.
	 */
	public boolean optBoolean(int index) {
		return this.optBoolean(index, false);
	}

	/**
	 * Get the optional boolean value associated with an index. It returns the
	 * defaultValue if there is no value at that index or if it is not a Boolean
	 * or the String "true" or "false" (case insensitive).
	 *
	 * @param index
	 *			The index must be between 0 and length() - 1.
	 * @param defaultValue
	 *			A boolean default.
	 * @return The truth.
	 */
	public boolean optBoolean(int index, boolean defaultValue) {
		try {
			return this.getBoolean(index);
		} catch (@SuppressWarnings("unused") Exception e) {
			return defaultValue;
		}
	}

	/**
	 * Get the optional double value associated with an index. NaN is returned
	 * if there is no value for the index, or if the value is not a number and
	 * cannot be converted to a number.
	 *
	 * @param index
	 *			The index must be between 0 and length() - 1.
	 * @return The value.
	 */
	public double optDouble(int index) {
		return this.optDouble(index, Double.NaN);
	}

	/**
	 * Get the optional double value associated with an index. The defaultValue
	 * is returned if there is no value for the index, or if the value is not a
	 * number and cannot be converted to a number.
	 *
	 * @param index
	 *			subscript
	 * @param defaultValue
	 *			The default value.
	 * @return The value.
	 */
	public double optDouble(int index, double defaultValue) {
		try {
			return this.getDouble(index);
		} catch (@SuppressWarnings("unused") Exception e) {
			return defaultValue;
		}
	}

	/**
	 * Get the optional int value associated with an index. Zero is returned if
	 * there is no value for the index, or if the value is not a number and
	 * cannot be converted to a number.
	 *
	 * @param index
	 *			The index must be between 0 and length() - 1.
	 * @return The value.
	 */
	public int optInt(int index) {
		return this.optInt(index, 0);
	}

	/**
	 * Get the optional int value associated with an index. The defaultValue is
	 * returned if there is no value for the index, or if the value is not a
	 * number and cannot be converted to a number.
	 *
	 * @param index
	 *			The index must be between 0 and length() - 1.
	 * @param defaultValue
	 *			The default value.
	 * @return The value.
	 */
	public int optInt(int index, int defaultValue) {
		try {
			return this.getInt(index);
		} catch (@SuppressWarnings("unused") Exception e) {
			return defaultValue;
		}
	}

	/**
	 * Get the optional JSONArray associated with an index.
	 *
	 * @param index
	 *			subscript
	 * @return A JSONArray value, or null if the index has no value, or if the
	 *		 value is not a JSONArray.
	 */
	public JSONArray optJSONArray(int index) {
		Object o = this.opt(index);
		return o instanceof JSONArray ? (JSONArray) o : null;
	}

	/**
	 * Get the optional JSONObject associated with an index. Null is returned if
	 * the key is not found, or null if the index has no value, or if the value
	 * is not a JSONObject.
	 *
	 * @param index
	 *			The index must be between 0 and length() - 1.
	 * @return A JSONObject value.
	 */
	public JSONObject optJSONObject(int index) {
		Object o = this.opt(index);
		return o instanceof JSONObject ? (JSONObject) o : null;
	}

	/**
	 * Get the optional long value associated with an index. Zero is returned if
	 * there is no value for the index, or if the value is not a number and
	 * cannot be converted to a number.
	 *
	 * @param index
	 *			The index must be between 0 and length() - 1.
	 * @return The value.
	 */
	public long optLong(int index) {
		return this.optLong(index, 0);
	}

	/**
	 * Get the optional long value associated with an index. The defaultValue is
	 * returned if there is no value for the index, or if the value is not a
	 * number and cannot be converted to a number.
	 *
	 * @param index
	 *			The index must be between 0 and length() - 1.
	 * @param defaultValue
	 *			The default value.
	 * @return The value.
	 */
	public long optLong(int index, long defaultValue) {
		try {
			return this.getLong(index);
		} catch (@SuppressWarnings("unused") Exception e) {
			return defaultValue;
		}
	}

	/**
	 * Get the optional string value associated with an index. It returns an
	 * empty string if there is no value at that index. If the value is not a
	 * string and is not null, then it is coverted to a string.
	 *
	 * @param index
	 *			The index must be between 0 and length() - 1.
	 * @return A String value.
	 */
	public String optString(int index) {
		return this.optString(index, "");
	}

	/**
	 * Get the optional string associated with an index. The defaultValue is
	 * returned if the key is not found.
	 *
	 * @param index
	 *			The index must be between 0 and length() - 1.
	 * @param defaultValue
	 *			The default value.
	 * @return A String value.
	 */
	public String optString(int index, String defaultValue) {
		Object object = this.opt(index);
		return JSONObject.NULL.equals(object) ? defaultValue : object
				.toString();
	}

	/**
	 * Append a boolean value. This increases the array's length by one.
	 *
	 * @param value
	 *			A boolean value.
	 * @return this.
	 */
	public JSONArray put(boolean value) {
		this.put(value ? Boolean.TRUE : Boolean.FALSE);
		return this;
	}

	/**
	 * Put a value in the JSONArray, where the value will be a JSONArray which
	 * is produced from a Collection.
	 *
	 * @param value
	 *			A Collection value.
	 * @return this.
	 */
	public JSONArray put(Collection<Object> value) {
		this.put(new JSONArray(value));
		return this;
	}

	/**
	 * Append a double value. This increases the array's length by one.
	 *
	 * @param value
	 *			A double value.
	 * @return this.
	 */
	public JSONArray put(double value) {
		Double d = new Double(value);
		JSONObject.testValidity(d);
		this.put(d);
		return this;
	}

	/**
	 * Append an int value. This increases the array's length by one.
	 *
	 * @param value
	 *			An int value.
	 * @return this.
	 */
	public JSONArray put(int value) {
		this.put(new Integer(value));
		return this;
	}

	/**
	 * Append an long value. This increases the array's length by one.
	 *
	 * @param value
	 *			A long value.
	 * @return this.
	 */
	public JSONArray put(long value) {
		this.put(new Long(value));
		return this;
	}

	/**
	 * Put a value in the JSONArray, where the value will be a JSONObject which
	 * is produced from a Map.
	 *
	 * @param value
	 *			A Map value.
	 * @return this.
	 */
	public JSONArray put(Map<String, Object> value) {
		this.put(new JSONObject(value));
		return this;
	}

	/**
	 * Append an object value. This increases the array's length by one.
	 *
	 * @param value
	 *			An object value. The value should be a Boolean, Double,
	 *			Integer, JSONArray, JSONObject, Long, or String, or the
	 *			JSONObject.NULL object.
	 * @return this.
	 */
	public JSONArray put(Object value) {
		this.myArrayList.add(value);
		return this;
	}

	/**
	 * Put or replace a boolean value in the JSONArray. If the index is greater
	 * than the length of the JSONArray, then null elements will be added as
	 * necessary to pad it out.
	 *
	 * @param index
	 *			The subscript.
	 * @param value
	 *			A boolean value.
	 * @return this.
	 */
	public JSONArray put(int index, boolean value) {
		this.put(index, value ? Boolean.TRUE : Boolean.FALSE);
		return this;
	}

	/**
	 * Put a value in the JSONArray, where the value will be a JSONArray which
	 * is produced from a Collection.
	 *
	 * @param index
	 *			The subscript.
	 * @param value
	 *			A Collection value.
	 * @return this.
	 */
	public JSONArray put(int index, Collection<Object> value) {
		this.put(index, new JSONArray(value));
		return this;
	}

	/**
	 * Put or replace a double value. If the index is greater than the length of
	 * the JSONArray, then null elements will be added as necessary to pad it
	 * out.
	 *
	 * @param index
	 *			The subscript.
	 * @param value
	 *			A double value.
	 * @return this.
	 */
	public JSONArray put(int index, double value) {
		this.put(index, new Double(value));
		return this;
	}

	/**
	 * Put or replace an int value. If the index is greater than the length of
	 * the JSONArray, then null elements will be added as necessary to pad it
	 * out.
	 *
	 * @param index
	 *			The subscript.
	 * @param value
	 *			An int value.
	 * @return this.
	 */
	public JSONArray put(int index, int value) {
		this.put(index, new Integer(value));
		return this;
	}

	/**
	 * Put or replace a long value. If the index is greater than the length of
	 * the JSONArray, then null elements will be added as necessary to pad it
	 * out.
	 *
	 * @param index
	 *			The subscript.
	 * @param value
	 *			A long value.
	 * @return this.
	 */
	public JSONArray put(int index, long value) {
		this.put(index, new Long(value));
		return this;
	}

	/**
	 * Put a value in the JSONArray, where the value will be a JSONObject that
	 * is produced from a Map.
	 *
	 * @param index
	 *			The subscript.
	 * @param value
	 *			The Map value.
	 * @return this.
	 */
	public JSONArray put(int index, Map<String, Object> value) {
		this.put(index, new JSONObject(value));
		return this;
	}

	/**
	 * Put or replace an object value in the JSONArray. If the index is greater
	 * than the length of the JSONArray, then null elements will be added as
	 * necessary to pad it out.
	 *
	 * @param index
	 *			The subscript.
	 * @param value
	 *			The value to put into the array. The value should be a
	 *			Boolean, Double, Integer, JSONArray, JSONObject, Long, or
	 *			String, or the JSONObject.NULL object.
	 * @return this.
	 */
	public JSONArray put(int index, Object value) {
		JSONObject.testValidity(value);
		if (index < 0) {
			throw new IllegalArgumentException("JSONArray[" + index + "] not found.");
		}
		if (index < this.length()) {
			this.myArrayList.set(index, value);
		} else {
			while (index != this.length()) {
				this.put(JSONObject.NULL);
			}
			this.put(value);
		}
		return this;
	}

	/**
	 * Remove an index and close the hole.
	 *
	 * @param index
	 *			The index of the element to be removed.
	 * @return The value that was associated with the index, or null if there
	 *		 was no value.
	 */
	public Object remove(int index) {
		return index >= 0 && index < this.length()
			? this.myArrayList.remove(index)
			: null;
	}

	/**
	 * Determine if two JSONArrays are similar.
	 * They must contain similar sequences.
	 *
	 * @param other The other JSONArray
	 * @return true if they are equal
	 */
	public boolean similar(Object other) {
		if (!(other instanceof JSONArray)) {
			return false;
		}
		int len = this.length();
		if (len != ((JSONArray)other).length()) {
			return false;
		}
		for (int i = 0; i < len; i += 1) {
			Object valueThis = this.get(i);
			Object valueOther = ((JSONArray)other).get(i);
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
	}

	/**
	 * Produce a JSONObject by combining a JSONArray of names with the values of
	 * this JSONArray.
	 *
	 * @param names
	 *			A JSONArray containing a list of key strings. These will be
	 *			paired with the values.
	 * @return A JSONObject, or null if there are no names or if this JSONArray
	 *		 has no values.
	 */
	public JSONObject toJSONObject(JSONArray names) {
		if (names == null || names.length() == 0 || this.length() == 0) {
			return null;
		}
		JSONObject jo = new JSONObject();
		for (int i = 0; i < names.length(); i += 1) {
			jo.put(names.getString(i), this.opt(i));
		}
		return jo;
	}

	/**
	 * Make a JSON text of this JSONArray. For compactness, no unnecessary
	 * whitespace is added. If it is not possible to produce a syntactically
	 * correct JSON text then null will be returned instead. This could occur if
	 * the array contains an invalid number.
	 * <p>
	 * Warning: This method assumes that the data structure is acyclical.
	 *
	 * @return a printable, displayable, transmittable representation of the
	 *		 array.
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
	 * Make a prettyprinted JSON text of this JSONArray. Warning: This method
	 * assumes that the data structure is acyclical.
	 *
	 * @param indentFactor
	 *			The number of spaces to add to each level of indentation.
	 * @return a printable, displayable, transmittable representation of the
	 *		 object, beginning with <code>[</code>&nbsp;<small>(left
	 *		 bracket)</small> and ending with <code>]</code>
	 *		 &nbsp;<small>(right bracket)</small>.
	 * @throws JSONException Error
	 */
	public String toString(int indentFactor) throws JSONException {
		StringWriter sw = new StringWriter();
		synchronized (sw.getBuffer()) {
			return this.write(sw, indentFactor, 0).toString();
		}
	}

	/**
	 * Write the contents of the JSONArray as JSON text to a writer. For
	 * compactness, no whitespace is added.
	 * <p>
	 * Warning: This method assumes that the data structure is acyclical.
	 *
	 * @param writer Writer
	 * @return The writer.
	 * @throws JSONException Error
	 */
	public Writer write(Writer writer) throws JSONException {
		return this.write(writer, 0, 0);
	}

	/**
	 * Write the contents of the JSONArray as JSON text to a writer. For
	 * compactness, no whitespace is added.
	 * <p>
	 * Warning: This method assumes that the data structure is acyclical.
	 *
	 * @param writer Writer
	 * @param indentFactor
	 *			The number of spaces to add to each level of indentation.
	 * @param indent
	 *			The indention of the top level.
	 * @return The writer.
	 * @throws JSONException Error
	 */
	Writer write(Writer writer, int indentFactor, int indent)
			throws JSONException {
		try {
			boolean commanate = false;
			int length = this.length();
			writer.write('[');

			if (length == 1) {
				JSONObject.writeValue(writer, this.myArrayList.get(0),
						indentFactor, indent);
			} else if (length != 0) {
				final int newindent = indent + indentFactor;

				for (int i = 0; i < length; i += 1) {
					if (commanate) {
						writer.write(',');
					}
					if (indentFactor > 0) {
						writer.write('\n');
					}
					JSONObject.indent(writer, newindent);
					JSONObject.writeValue(writer, this.myArrayList.get(i),
							indentFactor, newindent);
					commanate = true;
				}
				if (indentFactor > 0) {
					writer.write('\n');
				}
				JSONObject.indent(writer, indent);
			}
			writer.write(']');
			return writer;
		} catch (IOException e) {
			throw new JSONException(e);
		}
	}
}
