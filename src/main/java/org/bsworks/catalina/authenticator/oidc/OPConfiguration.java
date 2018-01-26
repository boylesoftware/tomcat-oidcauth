package org.bsworks.catalina.authenticator.oidc;

import java.util.Set;

import org.bsworks.util.json.JSONObject;


/**
 * OpenID Provider (OP) configuration.
 *
 * @author Lev Himmelfarb
 */
class OPConfiguration {

	/**
	 * Issuer identifier.
	 */
	private final String issuer;

	/**
	 * Authorization endpoint URL.
	 */
	private final String authorizationEndpoint;

	/**
	 * Token endpoint URL.
	 */
	private final String tokenEndpoint;

	/**
	 * JSON Web Key Set document URL.
	 */
	private final String jwksUri;


	/**
	 * Create OpenID Connect provider configuration.
	 *
	 * @param discoveryDocument Discovery document.
	 */
	OPConfiguration(final JSONObject discoveryDocument) {

		this.issuer =
			requiredStringProp(discoveryDocument, "issuer");
		this.authorizationEndpoint =
			requiredStringProp(discoveryDocument, "authorization_endpoint");
		this.tokenEndpoint =
			requiredStringProp(discoveryDocument, "token_endpoint");
		// skip userinfo_endpoint
		this.jwksUri =
			requiredStringProp(discoveryDocument, "jwks_uri");
		// skip registration_endpoint
	}

	/**
	 * Get required string property from the discovery document.
	 *
	 * @param container The container of the property, which is the discovery
	 * document.
	 * @param propName Property name.
	 * @return Property value.
	 * @throws IllegalArgumentException If the property does not exist.
	 */
	private static String requiredStringProp(
			final JSONObject container, final String propName) {

		final String value = container.getString(propName, null);
		if (value == null)
			throw new IllegalArgumentException("The discovery document does not"
					+ " have \"" + propName + "\" property.");

		return value;
	}

	/**
	 * Get optional string property from the discovery document.
	 *
	 * @param container The container of the property, which is the discovery
	 * document.
	 * @param propName Property name.
	 * @return Property value, or {@code null} if not present.
	 */
	private static String stringProp(
			final JSONObject container, final String propName) {

		return container.getString(propName, null);
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
