package org.bsworks.util.json;

import java.io.IOException;
import java.io.Reader;
import java.util.ArrayDeque;
import java.util.Deque;


/**
 * @author levahim
 *
 */
public class JsonParser {

	private enum State {

		OUTSIDE,
		IN_OBJECT,
		IN_ARRAY,
		IN_STRING
	}



	public static void parse(final Reader in)
		throws IOException {

		final Deque<State> stateStack = new ArrayDeque<>();

		State state = State.OUTSIDE;

		boolean done = false;
		do {

			int c;
			do {
				c = in.read();
			} while ((c == ' ') || (c == '\t') || (c == '\n') || (c == '\r'));

			switch (state) {

			case OUTSIDE:
				switch (c) {
				case '{':
					break;
				case '[':
					break;
				default:
				}
				break;
			}
		} while (!done);
	}
}
