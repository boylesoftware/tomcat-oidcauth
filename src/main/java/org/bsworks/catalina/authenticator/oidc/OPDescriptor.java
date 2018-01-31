package org.bsworks.catalina.authenticator.oidc;

import java.net.MalformedURLException;
import java.net.URL;


/**
 * Descriptor of an OpenID Provider (OP) used to specify it for the
 * authenticator.
 *
 * @author Lev Himmelfarb
 */
class OPDescriptor {

	/**
	 * Issuer identifier.
	 */
	private final String issuer;

	/**
	 * OP configuration document URL.
	 */
	private final URL configurationDocumentUrl;

	/**
	 * Web-application's client ID for the OP.
	 */
	private final String clientId;

	/**
	 * Web-application's client secret for the OP.
	 */
	private final String clientSecret;

	/**
	 * Additional query string parameters for the OP's authorization endpoint.
	 */
	private final String additionalAuthorizationParams;


	/**
	 * Create new descriptor.
	 *
	 * @param definition OpenID Provider definition, which is a comma-separated
	 * string that includes OP's issuer ID, web-application's client ID,
	 * web-application's client secret and, optionally, additional query string
	 * parameters for the OP's authorization endpoint in
	 * {@code x-www-form-urlencoded} format.
	 * @throws IllegalArgumentException If the definition cannot be parsed.
	 */
	OPDescriptor(final String definition) {

		final String[] parts = definition.trim().split("\\s*,\\s*");
		if ((parts.length < 3) || (parts.length > 4))
			throw new IllegalArgumentException(
					"Invalid OP definition: expected 3 or 4 comma-separated" +
						" values.");
		int i = 0;
		this.issuer = parts[i++];
		this.clientId = parts[i++];
		this.clientSecret = parts[i++];
		this.additionalAuthorizationParams =
			(i < parts.length ? parts[i++] : null);

		try {
			this.configurationDocumentUrl = new URL(
					this.issuer + (this.issuer.endsWith("/") ? "" : "/") +
					".well-known/openid-configuration");
		} catch (final MalformedURLException e) {
			throw new IllegalArgumentException(
					"Invalid OP definition: the issuer identifier must be a" +
						" valid URL.", e);
		}
	}


	/**
	 * Get OP's issuer identifier.
	 *
	 * @return The issuer identifier.
	 */
	String getIssuer() {

		return this.issuer;
	}

	/**
	 * Get OP's configuration document URL.
	 *
	 * @return The configuration document URL.
	 */
	URL getConfigurationDocumentUrl() {

		return this.configurationDocumentUrl;
	}

	/**
	 * Get web-application's client ID for the OP.
	 *
	 * @return The client ID.
	 */
	String getClientId() {

		return this.clientId;
	}

	/**
	 * Get web-application's client secret for the OP.
	 *
	 * @return The client secret.
	 */
	String getClientSecret() {

		return this.clientSecret;
	}

	/**
	 * Get optional additional query string parameters to send to the OP's
	 * authorization endpoint.
	 * 
	 * @return The parameters in {@code x-www-form-urlencoded} format, or
	 * {@code null} if none.
	 */
	String getAdditionalAuthorizationParams() {

		return this.additionalAuthorizationParams;
	}
}
