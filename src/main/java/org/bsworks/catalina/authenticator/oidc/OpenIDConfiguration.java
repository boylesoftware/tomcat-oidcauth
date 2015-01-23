package org.bsworks.catalina.authenticator.oidc;

import org.bsworks.util.json.JSONObject;


/**
 * OpenID Connect provider configuration.
 *
 * @author Lev Himmelfarb
 */
class OpenIDConfiguration {

	/**
	 * Name of the property in the discovery document that contains the
	 * issuer identifier.
	 */
	private static final String ISS_PROPNAME = "issuer";

	/**
	 * Name of the property in the discovery document that contains the
	 * authorization endpoint.
	 */
	private static final String AUTH_EP_PROPNAME = "authorization_endpoint";

	/**
	 * Name of the property in the discovery document that contains the token
	 * endpoint.
	 */
	private static final String TOKEN_EP_PROPNAME = "token_endpoint";


	/**
	 * The issuer identifier.
	 */
	private final String issuer;

	/**
	 * Authorization endpoint.
	 */
	private final String authorizationEndpoint;

	/**
	 * Token endpoint.
	 */
	private final String tokenEndpoint;


	/**
	 * Create OpenID Connect provider configuration.
	 *
	 * @param discoveryDocument Discovery document.
	 */
	OpenIDConfiguration(final JSONObject discoveryDocument) {

		this.issuer = discoveryDocument.getString(ISS_PROPNAME, null);
		if (this.issuer == null)
			throw new IllegalArgumentException("The discovery document does not"
					+ " contain \"" + ISS_PROPNAME + "\" property.");
		this.authorizationEndpoint =
			discoveryDocument.getString(AUTH_EP_PROPNAME, null);
		if (this.authorizationEndpoint == null)
			throw new IllegalArgumentException("The discovery document does not"
					+ " contain \"" + AUTH_EP_PROPNAME + "\" property.");
		this.tokenEndpoint =
			discoveryDocument.getString(TOKEN_EP_PROPNAME, null);
		if (this.tokenEndpoint == null)
			throw new IllegalArgumentException("The discovery document does not"
					+ " contain \"" + TOKEN_EP_PROPNAME + "\" property.");
	}


	/**
	 * Get issuer identifier.
	 *
	 * @return Issuer identifier.
	 */
	String getIssuer() {

		return this.issuer;
	}

	/**
	 * Get authorization endpoint.
	 *
	 * @return Authorization endpoint URL.
	 */
	String getAuthorizationEndpoint() {

		return this.authorizationEndpoint;
	}

	/**
	 * Get token endpoint.
	 *
	 * @return Token endpoint URL.
	 */
	String getTokenEndpoint() {

		return this.tokenEndpoint;
	}
}
