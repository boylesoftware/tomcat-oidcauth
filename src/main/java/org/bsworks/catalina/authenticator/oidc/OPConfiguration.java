package org.bsworks.catalina.authenticator.oidc;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;

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
	 * The JWK set provider.
	 */
	private final ConfigProvider<JWKSet> jwksProvider;


	/**
	 * Construct OpenID Connect provider configuration from JSON document.
	 *
	 * @param document The JSON document.
	 *
	 * @throws IOException If an I/O error happens pre-loading the JWK set.
	 */
	OPConfiguration(final JSONObject document)
		throws IOException {

		this.issuer = document.getString("issuer");
		this.authorizationEndpoint =
			document.getString("authorization_endpoint");
		this.tokenEndpoint = document.getString("token_endpoint");

		final URL jwksUri;
		try {
			jwksUri = new URL(document.getString("jwks_uri"));
		} catch (final MalformedURLException e) {
			throw new IllegalArgumentException(
					"Invalid JWKS URI in the OP configuration.", e);
		}
		this.jwksProvider = new ConfigProvider<JWKSet>(jwksUri) {
			@Override
			protected JWKSet parseDocument(final JSONObject jwksDocument) {
				return new JWKSet(jwksDocument);
			}
		};
		this.jwksProvider.get();
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

	/**
	 * Get JWK set.
	 *
	 * @return The JWK set.
	 *
	 * @throws IOException If an I/O error happens loading the JWK set.
	 */
	JWKSet getJWKSet()
		throws IOException {

		return this.jwksProvider.get();
	}
}
