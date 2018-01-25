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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;


/**
 * See http://www.json.org/java/.
 *
 * @author JSON.org
 * @author Lev Himmelfarb
 */
public class JSONTokener {

	/**
	 * The input reader.
	 */
	private final Reader reader;

	/**
	 * Tells if end of input has been reached.
	 */
	private boolean eof;

	/**
	 * Current character index in the input.
	 */
	private int index;

	/**
	 * Current line in the input.
	 */
	private int line;

	/**
	 * Current character index in the current line in the input.
	 */
	private int character;

	/**
	 * Tells to use previously read character for the current character.
	 */
	private boolean usePrevious;

	/**
	 * Previously read character.
	 */
	private char previous;


	/**
	 * Create new tokenizer for the specified input reader.
	 *
	 * @param reader The JSON input reader.
	 */
	public JSONTokener(final Reader reader) {

		this.reader =
			(reader.markSupported() ? reader : new BufferedReader(reader));

		this.eof = false;
		this.index = 0;
		this.line = 1;
		this.character = 1;
		this.usePrevious = false;
		this.previous = 0;
	}


	/**
	 * Back up one character. This provides a sort of lookahead capability,
	 * so that you can test for a digit or letter before attempting to parse
	 * the next number or identifier.
	 */
	void back() {

		if (this.usePrevious || this.index <= 0)
			throw new IllegalStateException(
					"Stepping back two steps is not supported.");

		this.index--;
		this.character--;
		this.usePrevious = true;
		this.eof = false;
	}

	/**
	 * Get next character from the input skipping whitespace.
	 *
	 * @return Next non-whitespace character from the input, or 0 if there are
	 * no more characters.
	 *
	 * @throws IOException If an I/O error happens reading from the input.
	 */
	char nextClean()
		throws IOException {

		while (true) {
			final char c = this.next();
			if ((c == 0) || (c > ' '))
				return c;
		}
	}

	/**
	 * Get next value.
	 *
	 * @return Next value, which can be a {@link Boolean}, {@link Double},
	 * {@link Integer}, {@link JSONArray}, {@link JSONObject}, {@link Long},
	 * {@link String} or the {@link JSONObject#NULL} object.
	 *
	 * @throws JSONException If syntax error.
	 * @throws IOException If an I/O error happens reading from the input.
	 */
	Object nextValue()
		throws JSONException, IOException {

		char c = this.nextClean();
		switch (c) {
		case '"':
			return this.nextString();
		case '{':
			this.back();
			return new JSONObject(this);
		case '[':
			this.back();
			return new JSONArray(this);
		default:
		}

		final StringBuilder sb = new StringBuilder();
		while ((c >= ' ') && (",:]}/\\\"[{;=#".indexOf(c) < 0)) {
			sb.append(c);
			c = this.next();
		}
		this.back();

		final String string = sb.toString().trim();
		if (string.isEmpty())
			throw new JSONException(this, "Missing value.");

		return JSONObject.stringToValue(string);
	}

	/**
	 * Get characters up to the next close quote character. Backslash processing
	 * is done.
	 *
	 * @return The string.
	 *
	 * @throws JSONException If unterminated string or an illegal escape.
	 * @throws IOException If an I/O error happens reading from the input.
	 */
	private String nextString()
		throws JSONException, IOException {

		final StringBuilder sb = new StringBuilder();
		while (true) {
			char c = this.next();
			switch (c) {
			case 0:
			case '\n':
			case '\r':
				throw new JSONException(this, "Unterminated string.");
			case '\\':
				c = this.next();
				switch (c) {
				case 'b':
					sb.append('\b');
					break;
				case 't':
					sb.append('\t');
					break;
				case 'n':
					sb.append('\n');
					break;
				case 'f':
					sb.append('\f');
					break;
				case 'r':
					sb.append('\r');
					break;
				case 'u':
					try {
						sb.append((char) Integer.parseInt(this.next(4), 16));
					} catch (final NumberFormatException e) {
						throw new JSONException(this, "Illegal escape.", e);
					}
					break;
				case '"':
				case '\\':
				case '/':
					sb.append(c);
					break;
				default:
					throw new JSONException(this, "Illegal escape.");
				}
				break;
			default:
				if (c == '"')
					return sb.toString();
				sb.append(c);
			}
		}
	}

	/**
	 * Get next {@code n} characters.
	 *
	 * @param n Number of characters to take.
	 *
	 * @return String of {@code n} characters.
	 *
	 * @throws JSONException If there are not enough characters remaining in the
	 * input.
	 * @throws IOException If an I/O error happens reading from the input.
	 */
	private String next(final int n)
		throws JSONException, IOException {

		if (n == 0)
			return "";

		final char[] chars = new char[n];
		int pos = 0;
		while (pos < n) {
			chars[pos] = this.next();
			if (this.eof && !this.usePrevious)
				throw new JSONException(this, "Substring bounds error.");
			pos++;
		}

		return new String(chars);
	}

	/**
	 * Get next character in the input.
	 *
	 * @return The next character, or 0 if past the end of the input.
	 *
	 * @throws IOException If an I/O error happens reading from the input.
	 */
	private char next()
		throws IOException {

		int c;
		if (this.usePrevious) {
			this.usePrevious = false;
			c = this.previous;
		} else {
			c = this.reader.read();
			if (c <= 0) {
				this.eof = true;
				c = 0;
			}
		}

		this.index++;
		if (this.previous == '\r') {
			this.line++;
			this.character = (c == '\n' ? 0 : 1);
		} else if (c == '\n') {
			this.line++;
			this.character = 0;
		} else {
			this.character++;
		}

		this.previous = (char) c;

		return this.previous;
	}

	/**
	 * Get current line in the input.
	 *
	 * @return Line number, starting from 1.
	 */
	int getLine() {

		return this.line;
	}

	/**
	 * Get current character index in the current line in the input.
	 *
	 * @return Character number, starting from 1.
	 */
	int getCharacter() {

		return this.character;
	}
}
