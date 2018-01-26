package org.bsworks.catalina.authenticator.oidc;

import java.beans.PropertyChangeListener;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.Container;
import org.apache.catalina.Context;
import org.apache.catalina.CredentialHandler;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.Realm;
import org.apache.catalina.Session;
import org.apache.catalina.Wrapper;
import org.apache.catalina.authenticator.Constants;
import org.apache.catalina.authenticator.FormAuthenticator;
import org.apache.catalina.authenticator.SavedRequest;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.realm.RealmBase;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.codec.binary.Base64;
import org.apache.tomcat.util.descriptor.web.LoginConfig;
import org.apache.tomcat.util.descriptor.web.SecurityConstraint;
import org.bsworks.util.json.JSONException;
import org.bsworks.util.json.JSONObject;
import org.bsworks.util.json.JSONTokener;
import org.ietf.jgss.GSSContext;


/**
 * <em>OpenID Connect</em> authenticator.
 *
 * @author Lev Himmelfarb
 */
public class OpenIDConnectAuthenticator
	extends FormAuthenticator {

	/**
	 * UTF-8 charset.
	 */
	private static final Charset UTF8 = Charset.forName("UTF-8");

	/**
	 * Name of the HTTP session note used to store the issuer ID of the OP used
	 * to authenticate the currently authenticated principal.
	 */
	private static final String SESS_OIDC_ISSUER_NOTE =
		"org.bsworks.catalina.session.ISSUER";


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
	 * realm.
	 */
	protected String usernameClaim = "sub";

	/**
	 * Space separated list of scopes to add to "openid" scope in the
	 * authorization endpoint request.
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
	 * @param providers The providers configuration, which is a whitespace
	 * separated list of descriptors, one for each configured provider. Each
	 * descriptor is a comma-separated string that includes OP's issuer ID,
	 * web-application's client ID, web-application's client secret and,
	 * optionally, additional query string parameters for the OP's authorization
	 * endpoint in {@code x-www-form-urlencoded} format.
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
		final String[] opDefs = this.providers.trim().split("\\s+");
		final List<OPDescriptor> opDescs = new ArrayList<>(opDefs.length);
		for (final String opDef : opDefs)
			opDescs.add(new OPDescriptor(opDef));
		this.ops = new OPConfigurationsProvider(opDescs);

		// preload provider configurations and detect any errors
		try {
			for (final OPDescriptor opDesc : opDescs)
				this.ops.getOPConfiguration(opDesc.getIssuer());
		} catch (final IOException | JSONException e) {
			throw new LifecycleException("OpenIDConnectAuthenticator could not"
					+ " load OpenID Connect Provider configuration.", e);
		}

		// proceed with initialization
		super.startInternal();
	}

	/* (non-Javadoc)
	 * See overridden method.
	 */
	@Override
	protected boolean doAuthenticate(final Request request,
			final HttpServletResponse response) throws IOException {

		final boolean debug = this.log.isDebugEnabled();

		// check if already authenticated
		if (this.checkForCachedAuthentication(request, response, true))
			return true;

		// the session
		Session session = null;

		// check if caching principal is disabled, but we have reauth info
		if (!this.cache) {

			// get/start session
			session = request.getSessionInternal(true);

			if (debug)
				this.log.debug("checking for reauthenticate in session "
						+ session);

			// check if auth info is in the session
			final String username =
				(String) session.getNote(Constants.SESS_USERNAME_NOTE);
			if (username != null) {

				Principal principal = null;

				final String issuer =
					(String) session.getNote(SESS_OIDC_ISSUER_NOTE);
				final String password =
					(String) session.getNote(Constants.SESS_PASSWORD_NOTE);

				// get the principal from the realm
				if (issuer != null) {
					if (debug)
						this.log.debug("reauthenticating username \""
								+ username + "\" authenticated by " + issuer);
					principal =
						this.context.getRealm().authenticate(username);
				} else if (password != null) {
					if (debug)
						this.log.debug("reauthenticating username \""
								+ username + "\" using password");
					principal =
						this.context.getRealm().authenticate(
								username, password);
				}

				// complete if successfully reauthenticated
				if (principal != null) {
					session.setNote(Constants.FORM_PRINCIPAL_NOTE, principal);
					if (!this.matchRequest(request)) {
						this.register(request, response, principal,
								HttpServletRequest.FORM_AUTH, username,
								password);
						return true;
					}
				}

				// failed reauthentication
				if (debug)
					this.log.debug("reauthentication failed, proceed normally");
			}
		}

		// check if resubmit after successful authentication
		if (this.matchRequest(request)) {

			// get session
			if (session == null)
				session = request.getSessionInternal(true);
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

			// if principal is cached, remove auth info from the session
			if (this.cache) {
				session.removeNote(Constants.SESS_USERNAME_NOTE);
				session.removeNote(Constants.SESS_PASSWORD_NOTE);
				session.removeNote(SESS_OIDC_ISSUER_NOTE);
			}

			// restore original request
			if (this.restoreRequest(request, session)) {
				if (debug)
					this.log.debug("proceed to restored request");
				return true;
			} else {
				if (debug)
					this.log.debug("restore of original request failed");
				response.sendError(HttpServletResponse.SC_BAD_REQUEST);
				return false;
			}
		}

        // Acquire references to objects we will need to evaluate
        String contextPath = request.getContextPath();
        String requestURI = request.getDecodedRequestURI();

        // Is this the action request from the login page?
        boolean loginAction =
            requestURI.startsWith(contextPath) &&
            requestURI.endsWith(Constants.FORM_ACTION);

        LoginConfig config = context.getLoginConfig();

        // No -- Save this request and redirect to the form login page
        if (!loginAction) {
            // If this request was to the root of the context without a trailing
            // '/', need to redirect to add it else the submit of the login form
            // may not go to the correct web application
            if (request.getServletPath().length() == 0 && request.getPathInfo() == null) {
                StringBuilder location = new StringBuilder(requestURI);
                location.append('/');
                if (request.getQueryString() != null) {
                    location.append('?');
                    location.append(request.getQueryString());
                }
                response.sendRedirect(response.encodeRedirectURL(location.toString()));
                return false;
            }

            session = request.getSessionInternal(true);
            if (log.isDebugEnabled()) {
                log.debug("Save request in session '" + session.getIdInternal() + "'");
            }
            try {
                saveRequest(request, session);
            } catch (IOException ioe) {
                log.debug("Request body too big to save during authentication");
                response.sendError(HttpServletResponse.SC_FORBIDDEN,
                        sm.getString("authenticator.requestBodyTooBig"));
                return false;
            }
            forwardToLoginPage(request, response, config);
            return false;
        }

        // Yes -- Acknowledge the request, validate the specified credentials
        // and redirect to the error page if they are not correct
        request.getResponse().sendAcknowledgement();
        Realm realm = context.getRealm();
        if (characterEncoding != null) {
            request.setCharacterEncoding(characterEncoding);
        }
        String username = request.getParameter(Constants.FORM_USERNAME);
        String password = request.getParameter(Constants.FORM_PASSWORD);
        if (log.isDebugEnabled()) {
            log.debug("Authenticating username '" + username + "'");
        }
        principal = realm.authenticate(username, password);
        if (principal == null) {
            forwardToErrorPage(request, response, config);
            return false;
        }

        if (log.isDebugEnabled()) {
            log.debug("Authentication of '" + username + "' was successful");
        }

        if (session == null) {
            session = request.getSessionInternal(false);
        }
        if (session == null) {
            if (containerLog.isDebugEnabled()) {
                containerLog.debug
                    ("User took so long to log on the session expired");
            }
            if (landingPage == null) {
                response.sendError(HttpServletResponse.SC_REQUEST_TIMEOUT,
                        sm.getString("authenticator.sessionExpired"));
            } else {
                // Make the authenticator think the user originally requested
                // the landing page
                String uri = request.getContextPath() + landingPage;
                SavedRequest saved = new SavedRequest();
                saved.setMethod("GET");
                saved.setRequestURI(uri);
                saved.setDecodedRequestURI(uri);
                request.getSessionInternal(true).setNote(
                        Constants.FORM_REQUEST_NOTE, saved);
                response.sendRedirect(response.encodeRedirectURL(uri));
            }
            return false;
        }

        // Save the authenticated Principal in our session
        session.setNote(Constants.FORM_PRINCIPAL_NOTE, principal);

        // Save the username and password as well
        session.setNote(Constants.SESS_USERNAME_NOTE, username);
        session.setNote(Constants.SESS_PASSWORD_NOTE, password);

        // Redirect the user to the original request URI (which will cause
        // the original request to be restored)
        requestURI = savedRequestURL(session);
        if (log.isDebugEnabled()) {
            log.debug("Redirecting to original '" + requestURI + "'");
        }
        if (requestURI == null) {
            if (landingPage == null) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                        sm.getString("authenticator.formlogin"));
            } else {
                // Make the authenticator think the user originally requested
                // the landing page
                String uri = request.getContextPath() + landingPage;
                SavedRequest saved = new SavedRequest();
                saved.setMethod("GET");
                saved.setRequestURI(uri);
                saved.setDecodedRequestURI(uri);
                session.setNote(Constants.FORM_REQUEST_NOTE, saved);
                response.sendRedirect(response.encodeRedirectURL(uri));
            }
        } else {
            // Until the Servlet API allows specifying the type of redirect to
            // use.
            Response internalResponse = request.getResponse();
            String location = response.encodeRedirectURL(requestURI);
            if ("HTTP/1.1".equals(request.getProtocol())) {
                internalResponse.sendRedirect(location,
                        HttpServletResponse.SC_SEE_OTHER);
            } else {
                internalResponse.sendRedirect(location,
                        HttpServletResponse.SC_FOUND);
            }
        }
        return false;
	}

	public boolean doAuthenticate1(final Request request,
			final HttpServletResponse response)
		throws IOException {

		final boolean debug = this.log.isDebugEnabled();

		// check if already authenticated
		if (this.checkAuthenticated(request))
			return true;

		// get the session
		final Session session = request.getSessionInternal(true);

		// re-submit of the original request after successful authentication?
		final boolean resubmit = this.matchRequest(request);

		// have we authenticated this user before but have caching disabled?
		if (!this.cache) {
			if (debug)
				this.log.debug("caching is disabled, checking for"
						+ " reauthenticate in session "
						+ session.getIdInternal());

			// get username from the session
			final String username =
				(String) session.getNote(Constants.SESS_USERNAME_NOTE);
			if (username != null) {
				if (debug)
					this.log.debug("reauthenticating username \""
							+ username + "\"");

				// get principal from the realm
				final Principal principal = this.context.getRealm()
						.authenticate(username, username);
				if (principal != null) {

					// save principal in the session
					session.setNote(Constants.FORM_PRINCIPAL_NOTE, principal);

					// authenticate the request and exit with success
					if (!resubmit) {
						this.register(request, response, principal,
								this.getAuthMethod(), username, null);
						return true;
					}

					// resubmit requires original request restored, don't exit
					if (debug)
						this.log.debug("resubmit, continuing");

				} else { // realm rejected user from the session
					if (debug)
						this.log.debug("reauthentication failed, proceed"
								+ " normally");
				}
			}
		}

		// re-submit of the original request after successful authentication?
		if (resubmit) {
			if (debug)
				this.log.debug("resubmit, restoring request from session "
						+ session.getIdInternal());

			// authenticate the request with the principal from the session
			this.register(request, response,
					(Principal) session.getNote(Constants.FORM_PRINCIPAL_NOTE),
					this.getAuthMethod(),
					(String) session.getNote(Constants.SESS_USERNAME_NOTE),
					null);

			// if we're caching principals we no longer need the username
			if (this.cache)
				session.removeNote(Constants.SESS_USERNAME_NOTE);

			// try to restore the original request
			if (!this.restoreRequest(request, session)) { // should no happen
				if (debug)
					this.log.debug("restore of original request failed");
				response.sendError(
						HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
				return false;
			}

			// done, proceed to processing of the restored original request
			if (debug)
				this.log.debug("proceed to restored request");
			return true;
		}

		// check if callback from the authorization server
		final String requestURI = request.getDecodedRequestURI();
		final boolean isCallback =
			(requestURI.startsWith(request.getContextPath())
					&& requestURI.endsWith(Constants.FORM_ACTION));

		// check if initial request to a protected resource
		if (!isCallback) {
			if (debug)
				this.log.debug("initial request to protected resource");

			// save request
			if (debug)
				this.log.debug("saving request in session "
						+ session.getIdInternal());
			try {
				this.saveRequest(request, session);
			} catch (final IOException e) {
				this.log.debug("request body is probably too big to save"
						+ " during authentication", e);
				response.sendError(HttpServletResponse.SC_FORBIDDEN,
						sm.getString("authenticator.requestBodyTooBig"));
				return false;
			}

			// redirect to the authorization server
			this.redirectToAuthorizationServer(request, response);

			// done, leave unauthenticated
			return false;
		}

		// callback from the authorization server, log the call
		if (debug) {
			final StringBuilder msg = new StringBuilder(256);
			msg.append("callback from the authorization server:");
			for (final Enumeration<String> en = request.getParameterNames();
					en.hasMoreElements();) {
				final String paramName = en.nextElement();
				msg.append("\n    ").append(paramName).append(": ")
					.append(request.getParameter(paramName));
			}
			this.log.debug(msg.toString());
		}

		// acknowledge the request
		request.getResponse().sendAcknowledgement();

		// process the callback and return the result
		return this.processAuthorizationServerCallback(request, response);
	}

	/**
	 * Check if the request is already authenticated. If not, also check if can
	 * be re-authenticated against an existing SSO session, if any.
	 *
	 * @param request The request.
	 *
	 * @return {@code true} if authenticated.
	 */
	protected boolean checkAuthenticated(final Request request) {

		final boolean debug = this.log.isDebugEnabled();

		// is the request already authenticated
		final Principal principal = request.getUserPrincipal();
		if (principal != null) {
			if (debug)
				this.log.debug("already authenticated as \""
						+ principal.getName() + "\"");

			// associate the session with any existing SSO session
			final String ssoId =
				(String) request.getNote(Constants.REQ_SSOID_NOTE);
			if (ssoId != null)
				this.associate(ssoId, request.getSessionInternal(true));

			// report as authenticated
			return true;
		}

		// is there an SSO session against which we can try to re-authenticate?
		final String ssoId = (String) request.getNote(Constants.REQ_SSOID_NOTE);
		if (ssoId != null) {
			if (debug)
				this.log.debug("SSO id " + ssoId
						+ ", attempting reauthentication");
			if (this.reauthenticateFromSSO(ssoId, request))
				return true;
		}

		// no, not authenticated
		return false;
	}

	/**
	 * Respond with a redirect to the OpenID Connect provider authorization
	 * endpoint.
	 *
	 * @param request The request.
	 * @param response The response.
	 *
	 * @throws IOException If an I/O error happens sending the response.
	 */
	protected void redirectToAuthorizationServer(final Request request,
			final HttpServletResponse response)
		throws IOException {

		final StringBuilder urlBuf = new StringBuilder(256);
		urlBuf.append(this.opConfig.getAuthorizationEndpoint())
			.append("?scope=")
				.append(URLEncoder.encode("openid email", UTF8.name()))
			.append("&response_type=code")
			.append("&client_id=")
				.append(URLEncoder.encode(this.clientId, UTF8.name()))
			.append("&redirect_uri=")
				.append(URLEncoder.encode(
						this.getBaseURL(request) + Constants.FORM_ACTION,
						UTF8.name()))
			.append("&state=")
				.append(URLEncoder.encode(
						request.getSessionInternal().getIdInternal(),
						UTF8.name()));
		if (this.hostedDomain != null)
			urlBuf.append("&hd=").append(
					URLEncoder.encode(this.hostedDomain, UTF8.name()));
		final String url = urlBuf.toString();

		if (this.log.isDebugEnabled())
			this.log.debug("redirecting to " + url);

		response.sendRedirect(url);
	}

	/**
	 * Process callback from the authorization server.
	 *
	 * @param request The request.
	 * @param response The response.
	 *
	 * @return {@code true} to proceed authenticated, {@code false} if
	 * authentication failed and the method sent the appropriate response.
	 *
	 * @throws IOException If an I/O error happens sending the client response.
	 */
	protected boolean processAuthorizationServerCallback(final Request request,
			final HttpServletResponse response)
		throws IOException {

		final boolean debug = this.log.isDebugEnabled();

		// check that the state matches the session
		final Session session = request.getSessionInternal();
		if (!session.getIdInternal().equals(
				request.getParameter("state"))) {
			if (debug)
				this.log.debug("received state does not match the session id");
			response.sendError(HttpServletResponse.SC_BAD_REQUEST);
			return false;
		}

		// check if error
		final String errorCode = request.getParameter("error");
		if (errorCode != null) {
			if (debug)
				this.log.debug("received error response " + errorCode);
			this.forwardToErrorPage(request, response,
					this.context.getLoginConfig());
			return false;
		}

		// get the authorization code
		final String code = request.getParameter("code");
		if (code == null) {
			if (debug)
				this.log.debug("request does not contain authorization code");
			response.sendError(HttpServletResponse.SC_BAD_REQUEST);
			return false;
		}

		// exchange the code
		final Map<String, String> params = new HashMap<>();
		params.put("grant_type", "authorization_code");
		params.put("code", code);
		params.put("redirect_uri",
				this.getBaseURL(request) + Constants.FORM_ACTION);
		params.put("client_id", this.clientId);
		if (this.clientSecret != null)
			params.put("client_secret", this.clientSecret);
		final JSONObject respJson;
		try {
			final String respEntity = this.httpPost(
					new URL(this.opConfig.getTokenEndpoint()),
					params, "application/json");
			if (respEntity == null) {
				if (debug)
					this.log.debug("exchange code call failed");
				this.forwardToErrorPage(request, response,
						this.context.getLoginConfig());
				return false;
			}
			respJson = new JSONObject(new JSONTokener(new StringReader(
					respEntity)));
		} catch (final JSONException | IOException e) {
			this.log.error("could not get valid response from authorization"
					+ " server's token endpoint", e);
			response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
			return false;
		}

		// check if error
		if (respJson.has("error")) {
			if (debug)
				this.log.debug("received error response "
						+ respJson.getString("error"));
			response.sendError(HttpServletResponse.SC_FORBIDDEN);
			return false;
		}

		// parse the ID token
		if (!respJson.has("id_token")) {
			if (debug)
				this.log.debug("no id_token in the response");
			response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
			return false;
		}
		final JSONObject idTokenHeader;
		final JSONObject idTokenPayload;
		final byte[] idTokenSignature;
		try {
			final String[] idTokenParts =
				respJson.getString("id_token").split("\\.");
			idTokenHeader = new JSONObject(new JSONTokener(new StringReader(
					new String(Base64.decodeBase64(idTokenParts[0]), UTF8))));
			idTokenPayload = new JSONObject(new JSONTokener(new StringReader(
					new String(Base64.decodeBase64(idTokenParts[1]), UTF8))));
			idTokenSignature = Base64.decodeBase64(idTokenParts[2]);
		} catch (final JSONException | ArrayIndexOutOfBoundsException e) {
			this.log.error("could not parse ID Token", e);
			response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
			return false;
		}
		if (debug) {
			this.log.debug("parsed ID Token:"
					+ "\n    header:    " + idTokenHeader
					+ "\n    payload:   " + idTokenPayload
					+ "\n    signature: " + Arrays.toString(idTokenSignature));
		}

		// validate the ID token
		if (!this.opConfig.getIssuer().equals(
				idTokenPayload.getString("iss", null))) {
			if (debug)
				this.log.debug("the ID Token issuer does not match");
			response.sendError(HttpServletResponse.SC_FORBIDDEN);
			return false;
		}
		// TODO: "aud" may be an array
		if (!this.clientId.equals(idTokenPayload.getString("aud", null))) {
			if (debug)
				this.log.debug("the ID Token audience does not match");
			response.sendError(HttpServletResponse.SC_FORBIDDEN);
			return false;
		}
		final String azp = idTokenPayload.getString("azp", null);
		if ((azp != null) && !azp.equals(this.clientId)) {
			if (debug)
				this.log.debug("the ID Token authorized party does not match");
			response.sendError(HttpServletResponse.SC_FORBIDDEN);
			return false;
		}
		if (!idTokenPayload.has("exp")
				|| (idTokenPayload.getLong("exp") * 1000L)
						<= System.currentTimeMillis()) {
			if (debug)
				this.log.debug("the ID Token expired or no expiration time");
			response.sendError(HttpServletResponse.SC_FORBIDDEN);
			return false;
		}

		// get username from the ID token
		final String username =
			idTokenPayload.getString(this.usernameClaim, null);
		if (username == null) {
			if (debug)
				this.log.debug("the ID Token does not contain the \""
						+ this.usernameClaim
						+ "\" claim used as the username claim.");
			response.sendError(HttpServletResponse.SC_FORBIDDEN);
			return false;
		}

		// authenticate the user in the realm
		if (debug)
			this.log.debug("authenticating user \"" + username + "\"");
		final Principal principal =
			this.context.getRealm().authenticate(username, username);
		if (principal == null) {
			if (debug)
				this.log.debug("failed to authenticate the user in the realm");
			this.forwardToErrorPage(request, response,
					this.context.getLoginConfig());
			return false;
		}
		if (debug)
			this.log.debug("successful authentication of \"" + username + "\"");

		// save the authenticated user in the session
		session.setNote(Constants.FORM_PRINCIPAL_NOTE, principal);
		session.setNote(Constants.SESS_USERNAME_NOTE, username);

		// redirect the user to the original request URI (which will resubmit)
		final String savedRequestURL = this.savedRequestURL(session);
		if (debug)
			this.log.debug("redirecting to original URL " + savedRequestURL);
		if (savedRequestURL == null) {

			// check that we have the landing page configured
			if (this.landingPage == null) {
				response.sendError(HttpServletResponse.SC_BAD_REQUEST,
						sm.getString("authenticator.formlogin"));
				return false;
			}

			// make it think the user originally requested the landing page
			final String uri = request.getContextPath() + this.landingPage;
			final SavedRequest savedRequest = new SavedRequest();
			savedRequest.setMethod("GET");
			savedRequest.setRequestURI(uri);
			savedRequest.setDecodedRequestURI(uri);
			session.setNote(Constants.FORM_REQUEST_NOTE, savedRequest);
			response.sendRedirect(response.encodeRedirectURL(uri));

		} else { // we have original request URL

			final Response internalResponse = request.getResponse();
			final String location = response.encodeRedirectURL(savedRequestURL);
			if ("HTTP/1.1".equals(request.getProtocol()))
				internalResponse.sendRedirect(location,
						HttpServletResponse.SC_SEE_OTHER);
			else
				internalResponse.sendRedirect(location,
						HttpServletResponse.SC_FOUND);
		}

		// redirect was sent in the response, don't proceed with the request
		return false;
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

	/**
	 * Get content from a URL using HTTP GET.
	 *
	 * @param url The URL.
	 * @param accept Accepted response content type, or {@code null} for
	 * anything.
	 *
	 * @return The response entity.
	 *
	 * @throws IOException If an I/O error happens.
	 */
	protected String httpGet(final URL url, final String accept)
		throws IOException {

		final boolean debug = this.log.isDebugEnabled();

		if (debug)
			this.log.debug("getting data from " + url);

		final HttpURLConnection con = (HttpURLConnection) url.openConnection();
		con.setConnectTimeout(this.httpConnectTimeout);
		con.setReadTimeout(this.httpReadTimeout);

		if (accept != null)
			con.addRequestProperty("Accept", accept);

		final ByteArrayOutputStream respBuf = new ByteArrayOutputStream(4096);
		try (final InputStream in = con.getInputStream()) {
			final byte[] buf = new byte[512];
			int n;
			while ((n = in.read(buf)) >= 0)
				respBuf.write(buf, 0, n);
		}

		final String resp = respBuf.toString(UTF8.name());
		if (debug)
			this.log.debug("received response: " + resp);

		return resp;
	}

	/**
	 * Get content from a URL using HTTP POST.
	 *
	 * @param url The URL.
	 * @param data Data to send.
	 * @param accept Accepted response content type, or {@code null} for
	 * anything.
	 *
	 * @return The response entity, or {@code null} if error response.
	 *
	 * @throws IOException If an I/O error happens.
	 */
	protected String httpPost(final URL url, final Map<String, String> data,
			final String accept)
		throws IOException {

		final boolean debug = this.log.isDebugEnabled();

		final StringBuilder body = new StringBuilder(512);
		for (final Map.Entry<String, String> entry : data.entrySet()) {
			final String paramName = entry.getKey();
			final String paramValue = entry.getValue();
			if (body.length() > 0)
				body.append('&');
			body.append(URLEncoder.encode(paramName, UTF8.name()))
				.append('=').append(URLEncoder.encode(paramValue, UTF8.name()));
		}

		if (debug)
			this.log.debug("posting data to " + url + ": " + body);

		final HttpURLConnection con = (HttpURLConnection) url.openConnection();
		con.setConnectTimeout(this.httpConnectTimeout);
		con.setReadTimeout(this.httpReadTimeout);
		con.setInstanceFollowRedirects(false);
		con.setDoOutput(true);

		if (accept != null)
			con.addRequestProperty("Accept", accept);

		final ByteArrayOutputStream respBuf = new ByteArrayOutputStream(4096);
		try (final OutputStream out = con.getOutputStream()) {
			out.write(body.toString().getBytes(UTF8.name()));
			out.flush();
			final int respCode = con.getResponseCode();
			if (respCode != HttpURLConnection.HTTP_OK) {
				this.log.debug("error response " + respCode
						+ ": " + con.getResponseMessage());
				con.disconnect();
				return null;
			}
			try (final InputStream in = con.getInputStream()) {
				final byte[] buf = new byte[512];
				int n;
				while ((n = in.read(buf)) >= 0)
					respBuf.write(buf, 0, n);
			}
		}

		final String resp = respBuf.toString(UTF8.name());
		if (debug)
			this.log.debug("received response: " + resp);

		return resp;
	}
}
