package org.bsworks.catalina.authenticator.oidc;

import java.io.IOException;
import java.security.Principal;
import java.util.Enumeration;

import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.Realm;
import org.apache.catalina.Session;
import org.apache.catalina.authenticator.Constants;
import org.apache.catalina.authenticator.FormAuthenticator;
import org.apache.catalina.connector.Request;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;


/**
 * <i>OpenID Connect</i> authenticator.
 *
 * @author Lev Himmelfarb
 */
public class OpenIDConnectAuthenticator
	extends FormAuthenticator {

	/**
	 * The log.
	 */
	protected final Log log = LogFactory.getLog(this.getClass());


	/**
	 * Returns "OIDC".
	 */
	@Override
	protected String getAuthMethod() {

		return "OIDC";
	}

	/* (non-Javadoc)
	 * See overridden method.
	 */
	@Override
	public boolean authenticate(final Request request,
			final HttpServletResponse response)
		throws IOException {

		final boolean debug = this.log.isDebugEnabled();

		// get SSO session id, if any
		final String ssoId = (String) request.getNote(Constants.REQ_SSOID_NOTE);

		// have we already authenticated someone?
		Principal principal = request.getUserPrincipal();
		if (principal != null) {
			if (debug)
				this.log.debug("already authenticated as \""
						+ principal.getName() + "\"");

			// associate the session with any existing SSO session
			if (ssoId != null)
				this.associate(ssoId, request.getSessionInternal(true));

			// proceed as authenticated
			return true;
		}

		// is there an SSO session against which we can try to reauthenticate?
		if (ssoId != null) {
			if (debug)
				this.log.debug("SSO id " + ssoId
						+ " set, attempting reauthentication");
			if (this.reauthenticateFromSSO(ssoId, request))
				return true;
		}

		// get the session
		final Session session = request.getSessionInternal(true);

		// get the realm
		final Realm realm = this.context.getRealm();

		// re-submit of the original request after successful authentication?
		final boolean resubmit = this.matchRequest(request);

		// have we authenticated this user before but have caching disabled?
		if (!this.cache) {
			if (debug)
				this.log.debug("checking for reauthenticate in session "
						+ session);

			// get username from the session
			final String username =
				(String) session.getNote(Constants.SESS_USERNAME_NOTE);
			if (username != null) {
				if (debug)
					this.log.debug("reauthenticating username \""
							+ username + "\"");

				// get principal from the realm
				principal = realm.authenticate(username, username);
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

				} else {
					if (debug)
						this.log.debug("reauthentication failed, proceed"
								+ " normally");
				}
			}
		}

		// re-submit of the original request after successful authentication?
		if (resubmit) {
			if (debug)
				this.log.debug("restore request from session "
						+ session.getIdInternal());

			// get principal from the session and authenticate the request
			principal =
				(Principal) session.getNote(Constants.FORM_PRINCIPAL_NOTE);
			this.register(request, response, principal, this.getAuthMethod(),
					(String) session.getNote(Constants.SESS_USERNAME_NOTE),
					null);

			// if we're caching principals we no longer need the username
			if (this.cache)
				session.removeNote(Constants.SESS_USERNAME_NOTE);

			// try to restore the original request
			if (this.restoreRequest(request, session)) {
				if (debug)
					this.log.debug("proceed to restored request");
				return true;
			}
			if (debug)
				this.log.debug("restore of original request failed");
			response.sendError(HttpServletResponse.SC_BAD_REQUEST);
			return false;
		}

		// check if initial request to a protected resource
		final String requestURI = request.getDecodedRequestURI();
		if (!requestURI.startsWith(request.getContextPath())
					|| !requestURI.endsWith(Constants.FORM_ACTION)) {

			// save request
			if (debug)
				this.log.debug("save request in session "
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

			// exit unauthenticated
			return false;
		}

		// coming back from the authorization server
		if (debug) {
			final StringBuilder msg = new StringBuilder(256);
			msg.append("coming back from the authorization server:");
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

		// check that the state matches the session
		

		// TODO Auto-generated method stub
		return false;
	}


	protected void redirectToAuthorizationServer(final Request request,
			final HttpServletResponse response) {
	}
}
