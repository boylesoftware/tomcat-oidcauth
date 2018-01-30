package org.bsworks.catalina.authenticator.oidc;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.HttpURLConnection;
import java.nio.charset.Charset;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.bsworks.util.json.JSONObject;
import org.bsworks.util.json.JSONTokener;


/**
 * Provider of the OpenID Provider (OP) configurations. The provider is
 * responsible for loading, parsing and caching the OP configuration documents.
 *
 * @author Lev Himmelfarb
 */
class OPConfigurationsProvider {

	/**
	 * Connect timeout for getting OP configuration document.
	 */
	private static final int CONNECT_TIMEOUT = 5000;

	/**
	 * Read timeout for getting OP configuration document.
	 */
	private static final int READ_TIMEOUT = 5000;

	/**
	 * UTF-8 charset.
	 */
	private static final Charset UTF8 = Charset.forName("UTF-8");

	/**
	 * Pattern used to extract max age from the cache control header.
	 */
	private static final Pattern MAX_AGE_PATTERN =
			Pattern.compile("\\bmax-age=(\\d+)");

	/**
	 * Milliseconds before the cached configuration expiration to reload it.
	 */
	private static final int EXP_GAP = 60000;

	/**
	 * Default cached configuration maximum age in milliseconds.
	 */
	private static final int DEFAULT_MAX_AGE = 24 * 3600000;


	/**
	 * Cached OP configuration.
	 */
	static final class CachedOPConfiguration {

		/**
		 * The configuration.
		 */
		OPConfiguration opConfig;

		/**
		 * Timestamp when the configuration expires.
		 */
		volatile long expireAt = 0;
	}


	/**
	 * The log.
	 */
	private final Log log = LogFactory.getLog(this.getClass());

	/**
	 * Supported OP descriptors by issuer ID.
	 */
	private final Map<String, OPDescriptor> opDescs;

	/**
	 * Cached OP configurations by issuer ID.
	 */
	private final Map<String, CachedOPConfiguration> cache =
		new HashMap<>();


	/**
	 * Create new provider.
	 *
	 * @param opDescs Descriptors of supported OPs.
	 */
	OPConfigurationsProvider(final Iterable<OPDescriptor> opDescs) {

		final Map<String, OPDescriptor> opDescsMap = new HashMap<>();
		for (final OPDescriptor opDesc : opDescs)
			if (opDescsMap.put(opDesc.getIssuer(), opDesc) != null)
				throw new IllegalArgumentException(
					"Issuer ID " + opDesc.getIssuer() +
						" is used for more than one OP.");
		this.opDescs = Collections.unmodifiableMap(opDescsMap);
	}


	/**
	 * Get OP configuration.
	 *
	 * @param issuer The OP's issuer ID.
	 *
	 * @return The configuration.
	 *
	 * @throws IllegalArgumentException If the issuer ID is unknown.
	 * @throws IOException If an I/O error happens loading the OP configuration
	 * document.
	 */
	OPConfiguration getOPConfiguration(final String issuer)
		throws IOException {

		// get cached configuration, or load it if not yet loaded
		CachedOPConfiguration cacheEl = this.cache.get(issuer);
		if (cacheEl == null) {
			synchronized (this.cache) {
				cacheEl = this.cache.get(issuer);
				if (cacheEl == null) {
					cacheEl = new CachedOPConfiguration();
					this.cache.put(issuer, cacheEl);
					this.loadOPConfiguration(issuer, cacheEl);
				}
			}
		}

		// check the cached configuration expiration
		if (System.currentTimeMillis() > cacheEl.expireAt - EXP_GAP) {
			synchronized (cacheEl) {
				if (System.currentTimeMillis() > cacheEl.expireAt - EXP_GAP)
					this.loadOPConfiguration(issuer, cacheEl);
			}
		}

		// return the configuration
		return cacheEl.opConfig;
	}

	/**
	 * Load OP configuration from the configuration document URL.
	 *
	 * @param issuer The OP's issuer ID.
	 * @param cacheEl Cache element into which the method loads the
	 * configuration and updates the expiration.
	 *
	 * @throws IllegalArgumentException If the issuer ID is unknown.
	 * @throws IOException If an I/O error happens loading the document from the
	 * URL.
	 */
	private void loadOPConfiguration(final String issuer,
			final CachedOPConfiguration cacheEl)
		throws IOException {

		// get OP descriptor
		final OPDescriptor opDesc = this.opDescs.get(issuer);
		if (opDesc == null)
			throw new IllegalArgumentException("Unknown issuer ID " + issuer);

		// log the load
		final boolean debug = this.log.isDebugEnabled();
		if (debug)
			this.log.debug("loading OP configuration document from "
					+ opDesc.getConfigurationDocumentUrl());

		// configure document load connection
		final HttpURLConnection con =
			(HttpURLConnection) opDesc.getConfigurationDocumentUrl()
				.openConnection();
		con.setConnectTimeout(CONNECT_TIMEOUT);
		con.setReadTimeout(READ_TIMEOUT);
		con.addRequestProperty("Accept", "application/json");

		// read and parse the document
		JSONObject opConfigDocument;
		try (final Reader in = new InputStreamReader(
				con.getInputStream(), UTF8)) {
			opConfigDocument = new JSONObject(new JSONTokener(in));
		}

		// log the response
		if (debug)
			this.log.debug("received OP configuration document: "
					+ opConfigDocument.toString());

		// set the OP configuration in the cache element
		cacheEl.opConfig = new OPConfiguration(opConfigDocument);

		// determine cache element expiration
		long responseDate = con.getDate();
		if (responseDate == 0)
			responseDate = System.currentTimeMillis();
		cacheEl.expireAt = 0;
		final String cacheControlHeader = con.getHeaderField("Cache-Control");
		if (cacheControlHeader != null) {
			final Matcher m = MAX_AGE_PATTERN.matcher(cacheControlHeader);
			if (m.find())
				cacheEl.expireAt = responseDate
					+ Integer.parseInt(m.group(1)) * 1000;
		}
		if (cacheEl.expireAt == 0)
			cacheEl.expireAt = con.getExpiration();
		if (cacheEl.expireAt == 0)
			cacheEl.expireAt = responseDate + DEFAULT_MAX_AGE;
	}
}
