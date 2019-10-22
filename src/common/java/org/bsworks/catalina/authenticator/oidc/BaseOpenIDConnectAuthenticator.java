package org.bsworks.catalina.authenticator.oidc;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.Session;
import org.apache.catalina.authenticator.Constants;
import org.apache.catalina.authenticator.FormAuthenticator;
import org.apache.catalina.authenticator.SavedRequest;
import org.apache.catalina.connector.Request;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.buf.HexUtils;
import org.apache.tomcat.util.descriptor.web.LoginConfig;
import org.bsworks.util.json.JSONArray;
import org.bsworks.util.json.JSONException;
import org.bsworks.util.json.JSONObject;
import org.bsworks.util.json.JSONTokener;


/**
 * Base <em>OpenID Connect</em> authenticator implementation for different
 * versions of <em>Tomcat</em>.
 *
 * @author Lev Himmelfarb
 */
public abstract class BaseOpenIDConnectAuthenticator
	extends FormAuthenticator {

	/**
	 * Authorization endpoint descriptor for the login page.
	 */
	public static final class AuthEndpointDesc {

		/**
		 * OP name.
		 */
		private final String name;

		/**
		 * Issuer ID.
		 */
		private final String issuer;

		/**
		 * Endpoint URL.
		 */
		private final String url;


		/**
		 * Create new descriptor.
		 *
		 * @param name OP name.
		 * @param issuer Issuer ID.
		 * @param url Endpoint URL.
		 */
		AuthEndpointDesc(final String name, final String issuer,
				final String url) {

			this.name = name;
			this.issuer = issuer;
			this.url = url;
		}


		/**
		 * Get OP name.
		 *
		 * @return The OP name.
		 */
		public String getName() {

			return this.name;
		}

		/**
		 * Get issuer ID.
		 *
		 * @return The issuer ID.
		 */
		public String getIssuer() {

			return this.issuer;
		}

		/**
		 * Get endpoint URL.
		 *
		 * @return The URL.
		 */
		public String getUrl() {

			return this.url;
		}
	}


	/**
	 * Authentication error descriptor for the error page.
	 */
	public static final class AuthErrorDesc {

		/**
		 * Error code.
		 */
		final String code;

		/**
		 * Optional error description.
		 */
		final String description;

		/**
		 * Optional URI of the page with the error information.
		 */
		final String infoPageURI;


		/**
		 * Create new descriptor using request parameters.
		 *
		 * @param request The request representing the error response.
		 */
		AuthErrorDesc(final Request request) {

			this.code = request.getParameter("error");
			this.description = request.getParameter("error_description");
			this.infoPageURI = request.getParameter("error_uri");
		}

		/**
		 * Create new descriptor using endpoint error response JSON.
		 *
		 * @param error The error response JSON.
		 */
		AuthErrorDesc(final JSONObject error) {

			this.code = error.getString("error");
			this.description = error.optString("error_description", null);
			this.infoPageURI = error.optString("error_uri", null);
		}


		/**
		 * Get error code.
		 *
		 * @return The code.
		 */
		public String getCode() {

			return this.code;
		}

		/**
		 * Get optional error description.
		 *
		 * @return The description, or {@code null}.
		 */
		public String getDescription() {

			return this.description;
		}

		/**
		 * Get optional URI of the page containing the error information.
		 *
		 * @return The page URI, or {@code null}.
		 */
		public String getInfoPageURI() {

			return this.infoPageURI;
		}
	}


	/**
	 * The successful authorization information derived from the token endpoint
	 * response.
	 */
	public static final class Authorization {

		/**
		 * Issuer ID.
		 */
		private final String issuer;

		/**
		 * Timestamp when the authorization was issued.
		 */
		private final Date issuedAt;

		/**
		 * Access token.
		 */
		private final String accessToken;

		/**
		 * Token type.
		 */
		private final String tokenType;

		/**
		 * Seconds to the authorization (access token) expiration.
		 */
		private final int expiresIn;

		/**
		 * Optional refresh token.
		 */
		private final String refreshToken;

		/**
		 * Optional scope.
		 */
		private final String scope;

		/**
		 * ID token.
		 */
		private final String idToken;


		/**
		 * Create new authorization descriptor.
		 *
		 * @param issuer Issuer ID.
		 * @param issuedAt Timestamp when the authorization was issued.
		 * @param tokenResponse Successful token endpoint response document.
		 */
		Authorization(final String issuer, final Date issuedAt,
				final JSONObject tokenResponse) {

			this.issuer = issuer;
			this.issuedAt = issuedAt;

			this.accessToken = tokenResponse.optString("access_token", null);
			this.tokenType = tokenResponse.optString("token_type", null);
			this.expiresIn = tokenResponse.optInt("expires_in", -1);
			this.refreshToken = tokenResponse.optString("refresh_token", null);
			this.scope = tokenResponse.optString("scope", null);
			this.idToken = tokenResponse.getString("id_token");
		}


		/**
		 * Get Issuer Identifier.
		 *
		 * @return The issuer ID.
		 */
		public String getIssuer() {

			return this.issuer;
		}

		/**
		 * Get timestamp when the authorization was issued.
		 *
		 * @return The timestamp (milliseconds).
		 */
		public Date getIssuedAt() {

			return this.issuedAt;
		}

		/**
		 * Get access token.
		 *
		 * @return The access token.
		 */
		public String getAccessToken() {

			return this.accessToken;
		}

		/**
		 * Get access token type (e.g. "Bearer").
		 *
		 * @return Access token type.
		 */
		public String getTokenType() {

			return this.tokenType;
		}

		/**
		 * Get access token expiration.
		 *
		 * @return Seconds after which the authorization (the access token)
		 * expires, or -1 if unspecified.
		 */
		public int getExpiresIn() {

			return this.expiresIn;
		}

		/**
		 * Get optional refresh token.
		 *
		 * @return The refresh token, or {@code null} if none.
		 */
		public String getRefreshToken() {

			return this.refreshToken;
		}

		/**
		 * Get optional scope.
		 *
		 * @return The scope, or {@code null} if none.
		 */
		public String getScope() {

			return this.scope;
		}

		/**
		 * Get ID token.
		 *
		 * @return The ID token.
		 */
		public String getIdToken() {

			return this.idToken;
		}


		/* (non-Javadoc)
		 * See overridden method.
		 */
		@Override
		public String toString() {

			final StringBuilder buf = new StringBuilder(1024);
			buf.append("Authorization issued at ")
				.append(DateFormat.getDateTimeInstance().format(this.issuedAt))
				.append(" by ").append(this.issuer).append(":");
			buf.append("\n  accessToken:  ").append(this.accessToken);
			buf.append("\n  tokenType:    ").append(this.tokenType);
			buf.append("\n  expiresIn:    ").append(this.expiresIn)
				.append(" seconds");
			buf.append("\n  refreshToken: ").append(this.refreshToken);
			buf.append("\n  scope:        ").append(this.scope);
			buf.append("\n  idToken:      ").append(this.idToken);

			return buf.toString();
		}
	}


	/**
	 * OP token endpoint response.
	 */
	private static final class TokenEndpointResponse {

		/**
		 * Response HTTP status code.
		 */
		final int responseCode;

		/**
		 * Response date.
		 */
		final Date responseDate;

		/**
		 * Response body.
		 */
		final JSONObject responseBody;


		/**
		 * Create new object representing a response.
		 *
		 * @param responseCode Response HTTP status code.
		 * @param responseDate Response date.
		 * @param responseBody Response body.
		 */
		TokenEndpointResponse(final int responseCode, final long responseDate,
				final JSONObject responseBody) {

			this.responseCode = responseCode;
			this.responseDate = new Date(
				responseDate != 0 ? responseDate : System.currentTimeMillis());
			this.responseBody = responseBody;
		}


		/* (non-Javadoc)
		 * @see java.lang.Object#toString()
		 */
		@Override
		public String toString() {

			return "status: " + this.responseCode + ", date: "
					+ DateFormat.getDateTimeInstance().format(this.responseDate)
					+ ", body: " + this.responseBody;
		}
	}


	/**
	 * Name of request attribute made available to the login page that maps
	 * configured OP issuer IDs to the corresponding authorization endpoint
	 * URLs.
	 */
	public static final String AUTHEPS_ATT = "org.bsworks.oidc.authEndpoints";

	/**
	 * Name of request attribute made available to the login page that tells if
	 * the form-based authentication is disabled.
	 */
	public static final String NOFORM_ATT = "org.bsworks.oidc.noForm";

	/**
	 * Name of request attribute made available on the login error page that
	 * contains the error descriptor.
	 */
	public static final String AUTHERROR_ATT = "org.bsworks.oidc.error";

	/**
	 * Name of session attribute used to store the {@link Authorization} object.
	 */
	public static final String AUTHORIZATION_ATT =
		"org.bsworks.oidc.authorization";

	/**
	 * UTF-8 charset.
	 */
	private static final Charset UTF8 = Charset.forName("UTF-8");

	/**
	 * URL-safe base64 decoder.
	 */
	private static final Base64.Decoder BASE64URL_DECODER =
		Base64.getUrlDecoder();

	/**
	 * Base64 encoder.
	 */
	private static final Base64.Encoder BASE64_ENCODER = Base64.getEncoder();

	/**
	 * Name of the HTTP session note used to store the {@link Authorization}
	 * object.
	 */
	private static final String SESS_OIDC_AUTH_NOTE =
		"org.bsworks.catalina.session.AUTHORIZATION";

	/**
	 * Name of the HTTP session note used to store the state value.
	 */
	private static final String SESS_STATE_NOTE =
		"org.bsworks.catalina.session.STATE";

	/**
	 * Pattern for the state parameter.
	 */
	private static final Pattern STATE_PATTERN = Pattern.compile(
			"^(\\d+)Z(.+)");

	/**
	 * Pattern used to parse providers configuration and convert it into JSON.
	 */
	private static final Pattern OP_CONF_LINE_PATTERN = Pattern.compile(
			"(\\w+)\\s*:\\s*(?:'([^']*)'|([^\\s,{}]+))");


	/**
	 * The log.
	 */
	protected final Log log = LogFactory.getLog(this.getClass());


	/**
	 * Virtual host base URI.
	 */
	protected String hostBaseURI;

	/**
	 * Providers configuration.
	 */
	protected String providers;

	/**
	 * Name of the claim in the ID Token used as the username in the users
	 * realm. Can be overridden for specific OPs.
	 */
	protected String usernameClaim = "sub";

	/**
	 * Space separated list of scopes to add to "openid" scope in the
	 * authorization endpoint request. Can be overridden for specific OPs.
	 */
	protected String additionalScopes;

	/**
	 * Tells if the form-based authentication is disabled.
	 */
	protected boolean noForm = false;

	/**
	 * HTTP connect timeout for OP endpoints.
	 */
	protected int httpConnectTimeout = 5000;

	/**
	 * HTTP read timeout for OP endpoints.
	 */
	protected int httpReadTimeout = 5000;


	/**
	 * Secure random number generator.
	 */
	private final SecureRandom rand = new SecureRandom();

	/**
	 * Configured OpenID Connect Provider descriptors.
	 */
	private List<OPDescriptor> opDescs;

	/**
	 * OpenID Connect Provider configurations provider.
	 */
	private OPConfigurationsProvider ops;


	/**
	 * Get virtual host base URI property.
	 *
	 * @return Host base URI.
	 */
	public String getHostBaseURI() {

		return this.hostBaseURI;
	}

	/**
	 * Set virtual host base URI property. The URI is used when constructing
	 * callback URLs for the web-application. If not set, the authenticator will
	 * attempt to construct it using the requests it receives.
	 *
	 * @param hostBaseURI Host base URI. Must not end with a "/". Should be an
	 * HTTPS URI.
	 */
	public void setHostBaseURI(final String hostBaseURI) {

		this.hostBaseURI = hostBaseURI;
	}

	/**
	 * Get providers configuration.
	 *
	 * @return The providers configuration
	 */
	public String getProviders() {

		return this.providers;
	}

	/**
	 * Set providers configuration.
	 *
	 * @param providers The providers configuration, which is a JSON-like array
	 * of descriptors, one for each configured provider. Unlike standard JSON,
	 * the syntax does not use double quotes around the property names and
	 * values (to make it XML attribute value friendly). The value can be
	 * surrounded with single quotes if it contains commas, curly braces or
	 * whitespace.
	 */
	public void setProviders(final String providers) {

		this.providers = providers;
	}

	/**
	 * Get name of the claim in the ID Token used as the username.
	 *
	 * @return The claim name.
	 */
	public String getUsernameClaim() {

		return this.usernameClaim;
	}

	/**
	 * Set name of the claim in the ID Token used as the username in the users
	 * realm. The default is "sub".
	 *
	 * @param usernameClaim The claim name.
	 */
	public void setUsernameClaim(final String usernameClaim) {

		this.usernameClaim = usernameClaim;
	}

	/**
	 * Get additional scopes for the authorization endpoint.
	 *
	 * @return The additional scopes.
	 */
	public String getAdditionalScopes() {

		return this.additionalScopes;
	}

	/**
	 * Set additional scopes for the authorization endpoint. The scopes are
	 * added to the required "openid" scope, which is always included.
	 *
	 * @param additionalScopes The additional scopes as a space separated list.
	 */
	public void setAdditionalScopes(final String additionalScopes) {

		this.additionalScopes = additionalScopes;
	}

	/**
	 * Tell if form-based authentication is disabled.
	 *
	 * @return {@code true} if disabled.
	 */
	public boolean isNoForm() {

		return this.noForm;
	}

	/**
	 * Set flag that tells if the form-based authentication should be disabled.
	 *
	 * @param noForm {@code true} to disabled form-based authentication.
	 */
	public void setNoForm(final boolean noForm) {

		this.noForm = noForm;
	}

	/**
	 * Get HTTP connect timeout used for server-to-server communication with the
	 * OpenID Connect provider.
	 *
	 * @return Timeout in milliseconds.
	 */
	public int getHttpConnectTimeout() {

		return this.httpConnectTimeout;
	}

	/**
	 * Set HTTP connect timeout used for server-to-server communication with the
	 * OpenID Connect provider. The default is 5000.
	 *
	 * @param httpConnectTimeout Timeout in milliseconds.
	 *
	 * @see URLConnection#setConnectTimeout(int)
	 */
	public void setHttpConnectTimeout(final int httpConnectTimeout) {

		this.httpConnectTimeout = httpConnectTimeout;
	}

	/**
	 * Get HTTP read timeout used for server-to-server communication with the
	 * OpenID Connect provider.
	 *
	 * @return Timeout in milliseconds.
	 */
	public int getHttpReadTimeout() {

		return this.httpReadTimeout;
	}

	/**
	 * Set HTTP read timeout used for server-to-server communication with the
	 * OpenID Connect provider. The default is 5000.
	 *
	 * @param httpReadTimeout Timeout in milliseconds.
	 *
	 * @see URLConnection#setReadTimeout(int)
	 */
	public void setHttpReadTimeout(final int httpReadTimeout) {

		this.httpReadTimeout = httpReadTimeout;
	}


	/* (non-Javadoc)
	 * See overridden method.
	 */
	@Override
	protected synchronized void startInternal()
			throws LifecycleException {

		// verify that providers are configured
		if (this.providers == null)
			throw new LifecycleException("OpenIDConnectAuthenticator requires"
						+ " \"providers\" property.");

		// parse provider definitions and create the configurations provider
		final String providersConf = this.providers.trim();
		if (providersConf.startsWith("[")) {
			final StringBuffer providersConfJSONBuf = new StringBuffer(512);
			final Matcher m = OP_CONF_LINE_PATTERN.matcher(providersConf);
			while (m.find()) {
				m.appendReplacement(providersConfJSONBuf,
					Matcher.quoteReplacement(
						"\"" + m.group(1) + "\": \""
						+ (m.group(2) != null ? m.group(2) : m.group(3))
						+ "\""));
			}
			m.appendTail(providersConfJSONBuf);
			final String providersConfJSON = providersConfJSONBuf.toString();
			try {
				this.log.debug(
					"parsing configuration JSON: " + providersConfJSON);
				final JSONArray opDefs = new JSONArray(new JSONTokener(
						new StringReader(providersConfJSON)));
				final int numOPs = opDefs.length();
				this.opDescs = new ArrayList<>(numOPs);
				for (int i = 0; i < numOPs; i++) {
					final Object opDef = opDefs.opt(i);
					if ((opDef == null) || !(opDef instanceof JSONObject))
						throw new LifecycleException("Expected an object at"
								+ " OpenIDConnectAuthenticator \"providers\""
								+ " array element " + i + ".");
					this.opDescs.add(new OPDescriptor((JSONObject) opDef,
							this.usernameClaim, this.additionalScopes));
				}
			} catch (final IOException | JSONException e) {
				throw new LifecycleException("OpenIDConnectAuthenticator could"
						+ " not parse \"providers\" property.", e);
			}
		} else { // deprecated syntax
			this.opDescs = this.parseDeprecatedOPDefs(providersConf);
		}
		this.ops = new OPConfigurationsProvider(this.opDescs);

		// preload provider configurations and detect any errors
		try {
			for (final OPDescriptor opDesc : this.opDescs)
				this.ops.getOPConfiguration(opDesc.getIssuer());
		} catch (final IOException | JSONException e) {
			throw new LifecycleException("OpenIDConnectAuthenticator could not"
					+ " load OpenID Connect Provider configuration.", e);
		}

		// proceed with initialization
		super.startInternal();
	}

	/**
	 * Parse deprecated OP configuration syntax.
	 *
	 * @param providersConf Configuration in deprecated syntax.
	 * @return The OP descriptors.
	 */
	@SuppressWarnings("deprecation")
	private List<OPDescriptor> parseDeprecatedOPDefs(
			final String providersConf) {

		final String[] defs = providersConf.split("\\s+");
		final List<OPDescriptor> descs = new ArrayList<>(defs.length);
		for (final String def : defs)
			descs.add(new OPDescriptor(def,
					this.usernameClaim, this.additionalScopes));

		return descs;
	}

	/**
	 * Perform authentication.
	 *
	 * @param request The request.
	 * @param response The response.
	 *
	 * @return Authentication result.
	 *
	 * @throws IOException If an I/O error happens.
	 */
	protected boolean performAuthentication(final Request request,
			final HttpServletResponse response)
		throws IOException {

		final boolean debug = this.log.isDebugEnabled();

		// check if already authenticated
		if (this.checkForCachedAuthentication(request, response, true))
			return true;

		// try to reauthenticate if caching principal is disabled
		if (!this.cache && this.reauthenticateNoCache(request, response))
			return true;

		// check if resubmit after successful authentication
		if (this.matchRequest(request))
			return this.processResubmit(request, response);

		// the request is not authenticated:

		// determine if authentication submission
		final String requestURI = request.getDecodedRequestURI();
		final boolean loginAction = (
				requestURI.startsWith(request.getContextPath()) &&
				requestURI.endsWith(Constants.FORM_ACTION));

		// check if regular unauthenticated request, not a submission
		if (!loginAction) {
			this.processUnauthenticated(request, response);
			return false;
		}

		// authentication submission (either form or OP response redirect):

		// acknowledge the request
		request.getResponse().sendAcknowledgement();

		// set response character encoding
		if (this.characterEncoding != null)
			request.setCharacterEncoding(this.characterEncoding);

		// get current session and check if expired
		final Session session = request.getSessionInternal(false);
		if (session == null) {

			// log using container log (why container?)
			if (this.containerLog.isDebugEnabled())
				this.containerLog.debug(
						"user took so long to log on the session expired");

			// redirect to the configured landing page, if any
			if (!this.redirectToLandingPage(request, response))
				response.sendError(HttpServletResponse.SC_REQUEST_TIMEOUT,
						sm.getString("authenticator.sessionExpired"));

			// done, authentication failure
			return false;
		}

		// the authenticated principal
		Principal principal = null;

		// check if OIDC authentication response or form submission
		if ((request.getParameter("code") != null)
				|| (request.getParameter("error") != null)) {
			principal = this.processAuthResponse(session,
					request);
		} else if (!this.noForm) { // form submission
			principal = this.processAuthFormSubmission(session,
					request.getParameter(Constants.FORM_USERNAME),
					request.getParameter(Constants.FORM_PASSWORD));
		}

		// check if authentication failure
		if (principal == null) {
			this.forwardToErrorPage(request, response,
					this.context.getLoginConfig());
			return false;
		}

		// successful authentication
		if (debug)
			this.log.debug("authentication of \"" + principal.getName()
				+ "\" was successful");

		// save the authenticated principal in our session
		session.setNote(Constants.FORM_PRINCIPAL_NOTE, principal);

		// get the original unauthenticated request URI
		final String origRequestURI = savedRequestURL(session);
		if (debug)
			this.log.debug("redirecting to original URI: " + origRequestURI);

		// if (somehow!) original URI is unavailable, go to the landing page
		if (origRequestURI == null) {
			if (!this.redirectToLandingPage(request, response))
				response.sendError(HttpServletResponse.SC_BAD_REQUEST,
						sm.getString("authenticator.formlogin"));
			return false;
		}

		// redirect to the original URI
		request.getResponse().sendRedirect(
				response.encodeRedirectURL(origRequestURI),
				("HTTP/1.1".equals(request.getProtocol()) ?
						HttpServletResponse.SC_SEE_OTHER :
							HttpServletResponse.SC_FOUND));

		// done, will be authenticated after the redirect
		return false;
	}

	/**
	 * If caching principal on the session by the authenticator is disabled,
	 * check if the session has authentication information (username, password
	 * or OP issuer ID) and if so, reauthenticate the user.
	 *
	 * @param request The request.
	 * @param response The response.
	 *
	 * @return {@code true} if was successfully reauthenticated and not further
	 * authentication action is required. If authentication logic should
	 * proceed, returns {@code false}.
	 */
	protected boolean reauthenticateNoCache(final Request request,
			final HttpServletResponse response) {

		// get session
		final Session session = request.getSessionInternal(true);

		final boolean debug = this.log.isDebugEnabled();
		if (debug)
			this.log.debug("checking for reauthenticate in session "
					+ session.getIdInternal());

		// check if authentication info is in the session
		final String username =
			(String) session.getNote(Constants.SESS_USERNAME_NOTE);
		if (username == null)
			return false;

		// get the rest of the authentication info
		final Authorization authorization =
			(Authorization) session.getNote(SESS_OIDC_AUTH_NOTE);
		final String password =
			(String) session.getNote(Constants.SESS_PASSWORD_NOTE);

		// get the principal from the realm (try to reauthenticate)
		Principal principal = null;
		if (authorization != null) { // was authenticated using OpenID Connect
			if (debug)
				this.log.debug("reauthenticating username \""
						+ username + "\" authenticated by "
						+ authorization.getIssuer());
			principal = this.context.getRealm().authenticate(
					username);
		} else if (password != null) { // was form-based authentication
			if (debug)
				this.log.debug("reauthenticating username \""
						+ username + "\" using password");
			principal = this.context.getRealm().authenticate(
					username, password);
		}

		// check if could not reauthenticate
		if (principal == null) {
			if (debug)
				this.log.debug("reauthentication failed, proceed normally");
			return false;
		}

		// set principal on the session
		session.setNote(Constants.FORM_PRINCIPAL_NOTE, principal);

		// check if resubmit after successful authentication
		if (this.matchRequest(request)) {
			if (debug)
				this.log.debug("reauthenticated username \"" + username
						+ "\" for resubmit after successful authentication");
			return false;
		}

		// successfully reauthenticated, register the principal
		if (debug)
			this.log.debug("successfully reauthenticated username \""
					+ username + "\"");
		this.register(request, response, principal,
				HttpServletRequest.FORM_AUTH, username, password);

		// no further authentication action required
		return true;
	}

	/**
	 * Process original request resubmit after successful authentication.
	 *
	 * @param request The request.
	 * @param response The response.
	 *
	 * @return {@code true} if success, {@code false} if failure, in which case
	 * an HTTP 400 response is sent back by this method.
	 *
	 * @throws IOException If an I/O error happens communicating with the
	 * client.
	 */
	protected boolean processResubmit(final Request request,
			final HttpServletResponse response)
		throws IOException {

		// get session
		final Session session = request.getSessionInternal(true);

		final boolean debug = this.log.isDebugEnabled();
		if (debug)
			this.log.debug("restore request from session "
					+ session.getIdInternal());

		// get authenticated principal and register it on the request
		final Principal principal =
			(Principal) session.getNote(Constants.FORM_PRINCIPAL_NOTE);
		this.register(request, response, principal,
				HttpServletRequest.FORM_AUTH,
				(String) session.getNote(Constants.SESS_USERNAME_NOTE),
				(String) session.getNote(Constants.SESS_PASSWORD_NOTE));

		// if principal is cached, remove authentication info from the session
		if (this.cache) {
			session.removeNote(Constants.SESS_USERNAME_NOTE);
			session.removeNote(Constants.SESS_PASSWORD_NOTE);
			session.removeNote(SESS_OIDC_AUTH_NOTE);
		}

		// try to restore original request
		if (!this.restoreRequest(request, session)) {
			if (debug)
				this.log.debug("restore of original request failed");
			response.sendError(HttpServletResponse.SC_BAD_REQUEST);
			return false;
		}

		// all good, no further authentication action is required
		if (debug)
			this.log.debug("proceed to restored request");
		return true;
	}

	/**
	 * Process regular unauthenticated request. Normally, saves the request in
	 * the session and forwards to the configured login page.
	 *
	 * @param request The request.
	 * @param response The response.
	 *
	 * @throws IOException If an I/O error happens communicating with the
	 * client.
	 */
	protected void processUnauthenticated(final Request request,
			final HttpServletResponse response)
		throws IOException {

		// If this request was to the root of the context without a trailing
		// "/", need to redirect to add it else the submit of the login form
		// may not go to the correct web application
		if ((request.getServletPath().length() == 0)
				&& (request.getPathInfo() == null)) {
			final StringBuilder location = new StringBuilder(
					request.getDecodedRequestURI());
			location.append('/');
			if (request.getQueryString() != null)
				location.append('?').append(request.getQueryString());
			response.sendRedirect(
					response.encodeRedirectURL(location.toString()));
			return;
		}

		// get session
		final Session session = request.getSessionInternal(true);

		final boolean debug = this.log.isDebugEnabled();
		if (debug)
			this.log.debug("save request in session "
					+ session.getIdInternal());

		// save original request in the session before forwarding to the login
		try {
			this.saveRequest(request, session);
		} catch (final IOException e) {
			this.log.debug("could not save request during authentication", e);
			response.sendError(HttpServletResponse.SC_FORBIDDEN,
					sm.getString("authenticator.requestBodyTooBig"));
			return;
		}

		// forward to the login page
		this.forwardToLoginPage(request, response,
				this.context.getLoginConfig());
	}

	/* (non-Javadoc)
	 * See overridden method.
	 */
	@Override
	protected void forwardToLoginPage(final Request request,
			final HttpServletResponse response, final LoginConfig config)
		throws IOException {

		// add login configuration request attributes for the page
		this.addLoginConfiguration(request);

		// proceed to the login page
		super.forwardToLoginPage(request, response, config);
	}

	/* (non-Javadoc)
	 * See overridden method.
	 */
	@Override
	protected void forwardToErrorPage(final Request request,
			final HttpServletResponse response, final LoginConfig config)
		throws IOException {

		// add login configuration request attributes for the page
		this.addLoginConfiguration(request);

		// proceed to the login error page
		super.forwardToErrorPage(request, response, config);
	}

	/**
	 * Add request attributes for the login or the login error page.
	 *
	 * @param request The request.
	 *
	 * @throws IOException If an I/O error happens.
	 */
	protected void addLoginConfiguration(final Request request)
		throws IOException {

		// generate state value and save it in the session
		final byte[] stateBytes = new byte[16];
		this.rand.nextBytes(stateBytes);
		final String state = HexUtils.toHexString(stateBytes);
		request.getSessionInternal(true).setNote(SESS_STATE_NOTE, state);

		// add OP authorization endpoints to the request for the login page
		final List<AuthEndpointDesc> authEndpoints = new ArrayList<>();
		final StringBuilder buf = new StringBuilder(128);
		for (int i = 0; i < this.opDescs.size(); i++) {
			final OPDescriptor opDesc = this.opDescs.get(i);

			// get the OP configuration
			final String issuer = opDesc.getIssuer();
			final OPConfiguration opConfig =
				this.ops.getOPConfiguration(issuer);

			// construct the authorization endpoint URL
			buf.setLength(0);
			buf.append(opConfig.getAuthorizationEndpoint());
			buf.append("?scope=openid");
			final String extraScopes = opDesc.getAdditionalScopes();
			if (extraScopes != null)
				buf.append(URLEncoder.encode(" " + extraScopes, UTF8.name()));
			buf.append("&response_type=code");
			buf.append("&client_id=").append(URLEncoder.encode(
					opDesc.getClientId(), UTF8.name()));
			buf.append("&redirect_uri=").append(URLEncoder.encode(
					this.getBaseURL(request) + Constants.FORM_ACTION,
					UTF8.name()));
			buf.append("&state=").append(i).append('Z').append(state);
			final String addlParams = opDesc.getExtraAuthEndpointParams();
			if (addlParams != null)
				buf.append('&').append(addlParams);

			// add the URL to the map
			authEndpoints.add(new AuthEndpointDesc(
					opDesc.getName(), issuer, buf.toString()));
		}
		request.setAttribute(AUTHEPS_ATT, authEndpoints);

		// add no form flag to the request
		request.setAttribute(NOFORM_ATT, Boolean.valueOf(this.noForm));
	}

	/**
	 * Process login form submission.
	 *
	 * @param session The session.
	 * @param username Submitted username.
	 * @param password Submitted password.
	 *
	 * @return The authenticated principal, or {@code null} if login failure.
	 */
	protected Principal processAuthFormSubmission(final Session session,
			final String username, final String password) {

		final boolean debug = this.log.isDebugEnabled();
		if (debug)
			this.log.debug("authenticating username \"" + username
					+ "\" using password");

		// authenticate principal in the realm
		final Principal principal =
			this.context.getRealm().authenticate(username, password);
		if (principal == null) {
			if (debug)
				this.log.debug("failed to authenticate the user in the realm");
			return null;
		}

		// save authentication info in the session
		session.setNote(Constants.SESS_USERNAME_NOTE, username);
		session.setNote(Constants.SESS_PASSWORD_NOTE, password);

		// return the principal
		return principal;
	}

	/**
	 * Process the authentication response and authenticate the user.
	 *
	 * @param session The session.
	 * @param request The request representing the authentication response.
	 *
	 * @return The authenticated principal, or {@code null} if could not
	 * authenticate.
	 *
	 * @throws IOException If an I/O error happens communicating with the OP.
	 */
	protected Principal processAuthResponse(final Session session,
			final Request request)
		throws IOException {

		final boolean debug = this.log.isDebugEnabled();
		if (debug)
			this.log.debug("authenticating user using OpenID Connect"
					+ " authentication response");

		// parse the state
		final String stateParam = request.getParameter("state");
		if (stateParam == null) {
			if (debug)
				this.log.debug("no state in the authentication response");
			return null;
		}
		final Matcher m = STATE_PATTERN.matcher(stateParam);
		if (!m.find()) {
			if (debug)
				this.log.debug("invalid state value in the authentication"
						+ " response");
			return null;
		}
		final int opInd = Integer.parseInt(m.group(1));
		final String state = m.group(2);

		// get OP descriptor from the state
		if (opInd >= this.opDescs.size()) {
			if (debug)
				this.log.debug("authentication response state contains invalid"
						+ " OP index");
			return null;
		}
		final OPDescriptor opDesc = this.opDescs.get(opInd);
		final String issuer = opDesc.getIssuer();
		if (debug)
			this.log.debug("processing authentication response from " + issuer);

		// match the session id from the state
		final String sessionState = (String) session.getNote(SESS_STATE_NOTE);
		session.removeNote(SESS_STATE_NOTE);
		if (!state.equals(sessionState)) {
			if (debug)
				this.log.debug("authentication response state does not match"
						+ " the session id");
			return null;
		}

		// check if error response
		final String errorCode = request.getParameter("error");
		if (errorCode != null) {
			final AuthErrorDesc authError = new AuthErrorDesc(request);
			if (debug)
				this.log.debug("authentication error response: "
						+ authError.getCode());
			request.setAttribute(AUTHERROR_ATT, authError);
			return null;
		}

		// get the authorization code
		final String authCode = request.getParameter("code");
		if (authCode == null) {
			if (debug)
				this.log.debug("no authorization code in the authentication"
						+ " response");
			return null;
		}

		// call the token endpoint, check if error and get the ID token
		final TokenEndpointResponse tokenResponse =
			this.callTokenEndpoint(opDesc, authCode, request);
		final String tokenErrorCode =
				tokenResponse.responseBody.optString("error");
		if ((tokenResponse.responseCode != HttpURLConnection.HTTP_OK) ||
				(tokenErrorCode.length() > 0)) {
			final AuthErrorDesc authError =
				new AuthErrorDesc(tokenResponse.responseBody);
			if (debug)
				this.log.debug("token error response: " + authError.getCode());
			request.setAttribute(AUTHERROR_ATT, authError);
			return null;
		}

		// create the authorization object
		final Authorization authorization =
			new Authorization(issuer, tokenResponse.responseDate,
					tokenResponse.responseBody);

		// decode the ID token
		final String[] idTokenParts = authorization.getIdToken().split("\\.");
		final JSONObject idTokenHeader = new JSONObject(new JSONTokener(
				new StringReader(new String(BASE64URL_DECODER.decode(
						idTokenParts[0]), UTF8))));
		final JSONObject idTokenPayload = new JSONObject(new JSONTokener(
				new StringReader(new String(BASE64URL_DECODER.decode(
						idTokenParts[1]), UTF8))));
		final byte[] idTokenSignature = BASE64URL_DECODER.decode(
				idTokenParts[2]);
		if (debug)
			this.log.debug("decoded ID token:"
					+ "\n    header:    " + idTokenHeader
					+ "\n    payload:   " + idTokenPayload
					+ "\n    signature: " + Arrays.toString(idTokenSignature));

		// validate the ID token:

		// validate issuer match
		if (!issuer.equals(idTokenPayload.getString("iss", null))) {
			if (debug)
				this.log.debug("the ID token issuer does not match");
			return null;
		}

		// validate audience match
		final Object audValue = idTokenPayload.get("aud", "");
		boolean audMatch = false;
		if (audValue instanceof JSONArray) {
			final JSONArray auds = (JSONArray) audValue;
			for (int n = auds.length() - 1; n >= 0; n--) {
				if (opDesc.getClientId().equals(auds.get(n))) {
					audMatch = true;
					break;
				}
			}
		} else {
			audMatch = opDesc.getClientId().equals(audValue);
		}
		if (!audMatch) {
			if (debug)
				this.log.debug("the ID token audience does not match");
			return null;
		}

		// validate authorized party
		if ((audValue instanceof JSONArray) && idTokenPayload.has("azp")) {
			if (!opDesc.getClientId().equals(idTokenPayload.get("azp"))) {
				if (debug)
					this.log.debug("the ID token authorized party does not"
							+ " match");
				return null;
			}
		}

		// validate token expiration
		if (!idTokenPayload.has("exp")
				|| (idTokenPayload.getLong("exp") * 1000L)
						<= System.currentTimeMillis()) {
			if (debug)
				this.log.debug("the ID token expired or no expiration time");
			return null;
		}

		// validate signature
		if (!this.isSignatureValid(opDesc, idTokenHeader,
				idTokenParts[0] + '.' + idTokenParts[1], idTokenSignature)) {
			if (debug)
				this.log.debug("invalid signature");
			return null;
		}
		if (debug)
			this.log.debug("signature validated successfully");

		// the token is valid, proceed:

		// get username from the ID token
		JSONObject usernameClaimContainer = idTokenPayload;
		final String[] usernameClaimParts = opDesc.getUsernameClaimParts();
		for (int i = 0; i < usernameClaimParts.length - 1; i++) {
			final Object v = usernameClaimContainer.opt(usernameClaimParts[i]);
			if ((v == null) || !(v instanceof JSONObject)) {
				if (debug)
					this.log.debug("the ID token does not contain the \""
							+ opDesc.getUsernameClaim()
							+ "\" claim used as the username claim");
				return null;
			}
			usernameClaimContainer = (JSONObject) v;
		}
		final String username = usernameClaimContainer.optString(
				usernameClaimParts[usernameClaimParts.length - 1], null);
		if (username == null) {
			if (debug)
				this.log.debug("the ID token does not contain the \""
						+ opDesc.getUsernameClaim()
						+ "\" claim used as the username claim");
			return null;
		}

		// authenticate the user in the realm
		if (debug)
			this.log.debug("authenticating user \"" + username + "\"");
		final Principal principal =
			this.context.getRealm().authenticate(username);
		if (principal == null) {
			if (debug)
				this.log.debug("failed to authenticate the user in the realm");
			return null;
		}

		// save authentication info in the session
		session.setNote(Constants.SESS_USERNAME_NOTE, principal.getName());
		session.setNote(SESS_OIDC_AUTH_NOTE, authorization);

		// save authorization in the session for the application
		session.getSession().setAttribute(AUTHORIZATION_ATT, authorization);

		// return the principal
		return principal;
	}

	/**
	 * Check if the JWT signature is valid.
	 *
	 * @param opDesc OP descriptor.
	 * @param header Decoded JWT header.
	 * @param data The JWT data (encoded header and payload).
	 * @param signature The signature from the JWT to test.
	 *
	 * @return {@code true} if valid.
	 *
	 * @throws IOException If an I/O error happens loading necessary data.
	 */
	protected boolean isSignatureValid(final OPDescriptor opDesc,
			final JSONObject header, final String data,
			final byte[] signature)
		throws IOException {

		try {

			final String sigAlg = header.optString("alg");

			switch (sigAlg) {

			case "RS256":

				final Signature sig = Signature.getInstance("SHA256withRSA");
				sig.initVerify(this.ops.getOPConfiguration(opDesc.getIssuer())
						.getJWKSet().getKey(header.getString("kid")));
				sig.update(data.getBytes("ASCII"));

				return sig.verify(signature);

			case "HS256":

				if (opDesc.getClientSecret() == null) {
					this.log.warn("client secret required for HS256 signature"
							+ " algorithm is not configured, reporting"
							+ " signature invalid");
					return false;
				}

				final Mac mac = Mac.getInstance("HmacSHA256");
				mac.init(new SecretKeySpec(BASE64URL_DECODER.decode(
						opDesc.getClientSecret()), "HmacSHA256"));
				mac.update(data.getBytes("ASCII"));
				final byte[] genSig = mac.doFinal();

				return Arrays.equals(genSig, signature);

			default:

				this.log.warn("unsupported token signature algorithm \""
						+ sigAlg + "\", skipping signature verification");

				return true;
			}

		} catch (final NoSuchAlgorithmException | SignatureException
				| InvalidKeyException | UnsupportedEncodingException e) {
			throw new RuntimeException(
					"Platform lacks signature algorithm support.", e);
		}
	}

	/**
	 * Call the OP's token endpoint and exchange the authorization code.
	 *
	 * @param opDesc OP descriptor.
	 * @param authCode The authorization code received from the authentication
	 * endpoint.
	 * @param request The request.
	 *
	 * @return The token endpoint response.
	 *
	 * @throws IOException If an I/O error happens communicating with the
	 * endpoint.
	 */
	protected TokenEndpointResponse callTokenEndpoint(final OPDescriptor opDesc,
			final String authCode, final Request request)
		throws IOException {

		final boolean debug = this.log.isDebugEnabled();

		// get the OP configuration
		final OPConfiguration opConfig =
			this.ops.getOPConfiguration(opDesc.getIssuer());
		final URL tokenEndpointURL = new URL(opConfig.getTokenEndpoint());

		// build POST body
		final StringBuilder buf = new StringBuilder(256);
		buf.append("grant_type=authorization_code");
		buf.append("&code=").append(URLEncoder.encode(authCode, UTF8.name()));
		buf.append("&redirect_uri=").append(URLEncoder.encode(
				this.getBaseURL(request) + Constants.FORM_ACTION, UTF8.name()));

		// configure connection
		final HttpURLConnection con =
			(HttpURLConnection) tokenEndpointURL.openConnection();
		con.setConnectTimeout(this.httpConnectTimeout);
		con.setReadTimeout(this.httpReadTimeout);
		con.setDoOutput(true);
		con.addRequestProperty("Content-Type",
				"application/x-www-form-urlencoded");
		con.addRequestProperty("Accept", "application/json");
		con.setInstanceFollowRedirects(false);

		// configure authentication
		switch (opDesc.getTokenEndpointAuthMethod()) {
		case CLIENT_SECRET_BASIC:
			con.addRequestProperty("Authorization",
				"Basic " + BASE64_ENCODER.encodeToString(
						(opDesc.getClientId() + ":" + opDesc.getClientSecret())
								.getBytes(UTF8)));
			break;
		case CLIENT_SECRET_POST:
			buf.append("&client_id=").append(URLEncoder.encode(
					opDesc.getClientId(), UTF8.name()));
			buf.append("&client_secret=").append(URLEncoder.encode(
					opDesc.getClientSecret(), UTF8.name()));
			break;
		default:
			// nothing
		}

		// finish POST body and log the call
		final String postBody = buf.toString();
		if (debug)
			this.log.debug("calling token endpoint at " + tokenEndpointURL
					+ " with: " + postBody);

		// send POST and read response
		JSONObject responseBody;
		try (final OutputStream out = con.getOutputStream()) {
			out.write(postBody.getBytes(UTF8.name()));
			out.flush();
			try (final Reader in = new InputStreamReader(
					con.getInputStream(), UTF8)) {
				responseBody = new JSONObject(new JSONTokener(in));
			} catch (final IOException e) {
				final InputStream errorStream = con.getErrorStream();
				if (errorStream == null)
					throw e;
				try (final Reader in = new InputStreamReader(errorStream, UTF8)) {
					responseBody = new JSONObject(new JSONTokener(in));
				}
			}
		}

		// create response object
		final TokenEndpointResponse response = new TokenEndpointResponse(
				con.getResponseCode(), con.getDate(), responseBody);

		// log the response
		if (debug)
			this.log.debug("received response: " + response.toString());

		// return the response
		return response;
	}

	/**
	 * Redirect to the configured landing page, if any.
	 *
	 * @param request The request.
	 * @param response The response.
	 *
	 * @return {@code true} if successfully redirected, {@code false} if no
	 * landing page is configured.
	 *
	 * @throws IOException If an I/O error happens communicating with the
	 * client.
	 */
	protected boolean redirectToLandingPage(final Request request,
			final HttpServletResponse response)
		throws IOException {

		// do we have landing page configured?
		if (this.landingPage == null)
			return false;

		// construct landing page URI
		final String uri = request.getContextPath() + this.landingPage;

		// make it think the user originally requested the landing page
		final SavedRequest savedReq = new SavedRequest();
		savedReq.setMethod("GET");
		savedReq.setRequestURI(uri);
		savedReq.setDecodedRequestURI(uri);
		request.getSessionInternal(true).setNote(
				Constants.FORM_REQUEST_NOTE, savedReq);

		// send the redirect
		response.sendRedirect(response.encodeRedirectURL(uri));

		// done, success
		return true;
	}

	/**
	 * Get web-application base URL (either from the {@code hostBaseURI}
	 * authenticator property or auto-detected from the request).
	 *
	 * @param request The request.
	 *
	 * @return Base URL.
	 */
	protected String getBaseURL(final Request request) {

		if (this.hostBaseURI != null)
			return this.hostBaseURI + request.getContextPath();

		final StringBuilder baseURLBuf = new StringBuilder(64);
		baseURLBuf.append("https://").append(request.getServerName());
		final int port = request.getServerPort();
		if (port != 443)
			baseURLBuf.append(':').append(port);
		baseURLBuf.append(request.getContextPath());

		return baseURLBuf.toString();
	}
}
