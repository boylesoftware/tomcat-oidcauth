package org.bsworks.catalina.authenticator.oidc;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.bsworks.util.json.JSONObject;
import org.bsworks.util.json.JSONTokener;


/**
 * Generic caching configuration document provider.
 *
 * @param <T> Configuration object type.
 *
 * @author Lev Himmelfarb
 */
abstract class ConfigProvider<T> {

	/**
	 * UTF-8 charset.
	 */
	private static final Charset UTF8 = Charset.forName("UTF-8");

	/**
	 * Connect timeout for getting the document.
	 */
	private static final int CONNECT_TIMEOUT = 5000;

	/**
	 * Read timeout for getting the document.
	 */
	private static final int READ_TIMEOUT = 5000;

	/**
	 * Pattern used to extract max age from the cache control header.
	 */
	private static final Pattern MAX_AGE_PATTERN =
			Pattern.compile("\\bmax-age=(\\d+)");

	/**
	 * Milliseconds before the cached document expiration to reload it.
	 */
	private static final int EXP_GAP = 60000;

	/**
	 * Default cached document maximum age in milliseconds.
	 */
	private static final int DEFAULT_MAX_AGE = 24 * 3600000;


	/**
	 * The log.
	 */
	private final Log log = LogFactory.getLog(this.getClass());

	/**
	 * Configuration document URL.
	 */
	private final URL documentURL;

	/**
	 * Cached configuration object.
	 */
	private T cachedConfig;

	/**
	 * Time when the cached configuration expires.
	 */
	private volatile long expireAt = 0;


	/**
	 * Create new provider.
	 *
	 * @param documentURL Configuration document URL.
	 */
	ConfigProvider(final URL documentURL) {

		this.documentURL = documentURL;
	}


	/**
	 * Get the configuration object.
	 *
	 * @return The configuration object.
	 *
	 * @throws IOException If an I/O error happens loading the configuration
	 * object.
	 */
	T get()
		throws IOException {

		if (System.currentTimeMillis() > this.expireAt - EXP_GAP) {
			synchronized (this) {
				if (System.currentTimeMillis() > this.expireAt - EXP_GAP) {
					this.expireAt = 0;
					this.loadDocument();
				}
			}
		}

		return this.cachedConfig;
	}

	/**
	 * Load the configuration document.
	 *
	 * @throws IOException If an I/O error happens.
	 */
	protected void loadDocument()
		throws IOException {

		// log the load
		final boolean debug = this.log.isDebugEnabled();
		if (debug)
			this.log.debug("loading document from " + this.documentURL);

		// configure document load connection
		final HttpURLConnection con =
			(HttpURLConnection) this.documentURL.openConnection();
		con.setConnectTimeout(CONNECT_TIMEOUT);
		con.setReadTimeout(READ_TIMEOUT);
		con.addRequestProperty("Accept",
			"application/jwk-set+json, application/json");

		// read and parse the document
		final JSONObject document;
		try (Reader in = new InputStreamReader(con.getInputStream(), UTF8)) {
			document = new JSONObject(new JSONTokener(in));
		}

		// log the response
		if (debug)
			this.log.debug("received document: " + document.toString());

		// parse and store the loaded configuration
		this.cachedConfig = this.parseDocument(document);

		// determine cache expiration
		long responseDate = con.getDate();
		if (responseDate == 0)
			responseDate = System.currentTimeMillis();
		final String cacheControlHeader = con.getHeaderField("Cache-Control");
		if (cacheControlHeader != null) {
			final Matcher m = MAX_AGE_PATTERN.matcher(cacheControlHeader);
			if (m.find())
				this.expireAt = responseDate
					+ Integer.parseInt(m.group(1)) * 1000;
		}
		if (this.expireAt == 0)
			this.expireAt = con.getExpiration();
		if (this.expireAt == 0)
			this.expireAt = responseDate + DEFAULT_MAX_AGE;
	}

	/**
	 * Parse document JSON into the configuration object.
	 *
	 * @param document Loaded JSON document.
	 *
	 * @return The configuration object.
	 */
	protected abstract T parseDocument(JSONObject document);
}
