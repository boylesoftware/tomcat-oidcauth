package org.bsworks.util.json;


/**
 * See http://www.json.org/java/.
 *
 * @author JSON.org
 * @author Lev Himmelfarb
 */
public class JSONException
	extends Exception {

	/**
	 * Serial version id.
	 */
	private static final long serialVersionUID = 1L;


	/**
	 * Create new exception.
	 *
	 * @param tok The tokenizer.
	 * @param message Error description.
	 */
	JSONException(final JSONTokener tok, final String message) {
		super("Invalid JSON at line " + tok.getLine() + ", col "
				+ tok.getCharacter() + ": " + message);
	}

	/**
	 * Create new exception.
	 *
	 * @param tok The tokenizer.
	 * @param message Error description.
	 * @param cause The cause.
	 */
	JSONException(final JSONTokener tok, final String message,
			final Throwable cause) {
		super("Invalid JSON at line " + tok.getLine() + ", col "
				+ tok.getCharacter() + ": " + message, cause);
	}

	/**
	 * Create new exception.
	 *
	 * @param cause The cause.
	 */
	JSONException(final Throwable cause) {
		super(cause.getMessage(), cause);
	}
}
