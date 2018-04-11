package org.bsworks.catalina.authenticator.oidc;

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;

import org.bsworks.util.json.JSONObject;


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
	 * OP name.
	 */
	private final String name;

	/**
	 * OP configuration document URL.
	 */
	private final URL configurationDocumentUrl;

	/**
	 * Web-application's client ID for the OP.
	 */
	private final String clientId;

	/**
	 * Optional web-application's client secret for the OP, or {@code null}.
	 */
	private final String clientSecret;

	/**
	 * Optional additional query string parameters for the OP's authorization
	 * endpoint, or {@code null}.
	 */
	private final String extraAuthEndpointParams;

	/**
	 * Authentication method for the OP's token endpoint.
	 */
	private final TokenEndpointAuthMethod tokenEndpointAuthMethod;

	/**
	 * Username claim.
	 */
	private final String usernameClaim;

	/**
	 * Username claim parts.
	 */
	private final String[] usernameClaimParts;

	/**
	 * Optional space separated list of additional scopes, or {@code null}.
	 */
	private final String additionalScopes;


	/**
	 * Create new descriptor.
	 *
	 * @param definition OpenID Provider definition, which is a comma-separated
	 * string that includes OP's issuer ID, web-application's client ID,
	 * web-application's client secret and, optionally, additional query string
	 * parameters for the OP's authorization endpoint in
	 * {@code x-www-form-urlencoded} format.
	 * @param defaultUsernameClaim Default username claim.
	 * @param defaultAdditionalScopes Optional default additional scopes, or
	 * {@code null}.
	 * @throws IllegalArgumentException If the definition cannot be parsed.
	 * @deprecated Use JSON-like providers configuration.
	 */
	@Deprecated
	OPDescriptor(final String definition, final String defaultUsernameClaim,
			final String defaultAdditionalScopes) {

		final String[] parts = definition.trim().split("\\s*,\\s*");
		if ((parts.length < 3) || (parts.length > 4))
			throw new IllegalArgumentException(
					"Invalid OP definition: expected 3 or 4 comma-separated" +
						" values.");
		int i = 0;
		this.issuer = parts[i++];
		this.name = this.issuer;
		this.clientId = parts[i++];
		final String secretVal = parts[i++];
		this.clientSecret = (secretVal.length() > 0 ? secretVal : null);
		this.extraAuthEndpointParams = (i < parts.length ? parts[i++] : null);
		this.tokenEndpointAuthMethod = (this.clientSecret != null ?
				TokenEndpointAuthMethod.CLIENT_SECRET_BASIC :
					TokenEndpointAuthMethod.NONE);
		this.usernameClaim = defaultUsernameClaim;
		this.usernameClaimParts = this.usernameClaim.split("\\.");
		this.additionalScopes = defaultAdditionalScopes;

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
	 * Create new descriptor.
	 *
	 * @param definition OpenID Provider definition JSON object.
	 * @param defaultUsernameClaim Default username claim.
	 * @param defaultAdditionalScopes Optional default additional scopes, or
	 * {@code null}.
	 * @throws IllegalArgumentException If the definition is invalid.
	 */
	OPDescriptor(final JSONObject definition, final String defaultUsernameClaim,
			final String defaultAdditionalScopes) {

		this.issuer = definition.optString("issuer", null);
		if (this.issuer == null)
			throw new IllegalArgumentException("Invalid OP definition:"
					+ " missing \"issuer\" property.");
		this.name = definition.optString("name", this.issuer);
		this.clientId = definition.optString("clientId", null);
		if (this.clientId == null)
			throw new IllegalArgumentException("Invalid OP definition:"
					+ " missing \"clientId\" property.");
		this.clientSecret = definition.optString("clientSecret", null);
		this.usernameClaim = definition.optString("usernameClaim",
				defaultUsernameClaim);
		this.usernameClaimParts = this.usernameClaim.split("\\.");
		this.additionalScopes = definition.optString("additionalScopes",
				defaultAdditionalScopes);

		final Object paramsObj = definition.opt("extraAuthEndpointParams");
		if (paramsObj != null) {
			if (!(paramsObj instanceof JSONObject))
				throw new IllegalArgumentException("Invalid OP definition:"
						+ " \"extraAuthEndpointParams\" property is not"
						+ " an object.");
			final JSONObject paramsJSON = (JSONObject) paramsObj;
			final StringBuilder buf = new StringBuilder(256);
			for (final String paramName : paramsJSON.keySet()) {
				if (buf.length() > 0)
					buf.append("&");
				try {
					buf.append(paramName).append("=").append(URLEncoder.encode(
							paramsJSON.optString(paramName), "UTF-8"));
				} catch (final UnsupportedEncodingException e) {
					throw new Error(
						"The platform does not support UTF-8 encoding.", e);
				}
			}
			this.extraAuthEndpointParams = buf.toString();
		} else {
			this.extraAuthEndpointParams = null;
		}

		try {
			this.tokenEndpointAuthMethod = TokenEndpointAuthMethod.valueOf(
					definition.optString("tokenEndpointAuthMethod",
						(this.clientSecret != null ?
							TokenEndpointAuthMethod.CLIENT_SECRET_BASIC :
								TokenEndpointAuthMethod.NONE)
						.name().toLowerCase()).toUpperCase());
		} catch (final IllegalArgumentException e) {
			throw new IllegalArgumentException("Invalid OP definition:"
					+ " \"tokenEndpointAuthMethod\" property has invalid"
					+ " value.", e);
		}
		switch (this.tokenEndpointAuthMethod) {
		case CLIENT_SECRET_BASIC:
		case CLIENT_SECRET_POST:
			if (this.clientSecret == null)
				throw new IllegalArgumentException("Invalid OP definition:"
						+ " \"clientSecret\" is required for the token endpoint"
						+ " authentication method.");
			break;
		case NONE:
			break;
		default:
			throw new IllegalArgumentException("Invalid OP definition:"
					+ " unsupported \"tokenEndpointAuthMethod\" property"
					+ " value.");
		}

		try {
			this.configurationDocumentUrl = new URL(definition.optString(
					"configurationDocumentUrl",
					this.issuer + (this.issuer.endsWith("/") ? "" : "/")
						+ ".well-known/openid-configuration"));
		} catch (final MalformedURLException e) {
			throw new IllegalArgumentException(
					"Invalid OP definition: the issuer identifier is not a" +
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
	 * Get application-specific OP name.
	 *
	 * @return The name.
	 */
	String getName() {

		return this.name;
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
	 * Get optional web-application's client secret for the OP.
	 *
	 * @return The client secret, or {@code null} if none.
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
	String getExtraAuthEndpointParams() {

		return this.extraAuthEndpointParams;
	}

	/**
	 * Get authentication method for the OP's token endpoint.
	 *
	 * @return The authentication method.
	 */
	TokenEndpointAuthMethod getTokenEndpointAuthMethod() {

		return this.tokenEndpointAuthMethod;
	}

	/**
	 * Get username claim.
	 *
	 * @return The username claim.
	 */
	String getUsernameClaim() {

		return this.usernameClaim;
	}

	/**
	 * Get username claim.
	 *
	 * @return Parts of the username claim path. Single element array if the
	 * claim is not nested.
	 */
	String[] getUsernameClaimParts() {

		return this.usernameClaimParts;
	}

	/**
	 * Get optional scopes to add to "openid".
	 *
	 * @return Space separated additional scopes, or {@code null} if none.
	 */
	String getAdditionalScopes() {

		return this.additionalScopes;
	}
}
