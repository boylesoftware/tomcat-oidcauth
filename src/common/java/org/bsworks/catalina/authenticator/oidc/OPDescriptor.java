package org.bsworks.catalina.authenticator.oidc;

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.regex.Pattern;

import org.bsworks.util.json.JSONObject;


/**
 * Descriptor of an OpenID Provider (OP) used to specify it for the
 * authenticator.
 *
 * @author Lev Himmelfarb
 */
class OPDescriptor {

	/**
	 * Default configuration retry timeout for optional OP.
	 */
	private static final int DEFAULT_CONFIG_RETRY_TIMEOUT = 10000;

	/**
	 * Issuer identifier.
	 */
	private final String issuer;

	/**
	 * Pattern for validating "iss" claim.
	 */
	private final Pattern validIssPattern;

	/**
	 * OP name.
	 */
	private final String name;

	/**
	 * OP configuration document URL.
	 */
	private final URL configUrl;

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
	 * HTTP connect timeout for OP endpoints.
	 */
	private final int endpointHttpConnectTimeout;

	/**
	 * HTTP read timeout for OP endpoints.
	 */
	private final int endpointHttpReadTimeout;

	/**
	 * HTTP connect timeout for OP configuration document URL.
	 */
	private final int configHttpConnectTimeout;

	/**
	 * HTTP read timeout for OP configuration document URL.
	 */
	private final int configHttpReadTimeout;

	/**
	 * HTTP connect timeout for OP JWKS URL.
	 */
	private final int jwksHttpConnectTimeout;

	/**
	 * HTTP read timeout for OP JWKS URL.
	 */
	private final int jwksHttpReadTimeout;

	/**
	 * Optional OP flag.
	 */
	private final boolean optional;

	/**
	 * Configuration retry timeout for optional OP.
	 */
	private final int configRetryTimeout;


	/**
	 * Create new descriptor.
	 *
	 * @param definition OpenID Provider definition, which is a comma-separated
	 * string that includes OP's issuer ID, web-application's client ID,
	 * web-application's client secret and, optionally, additional query string
	 * parameters for the OP's authorization endpoint in
	 * {@code x-www-form-urlencoded} format.
	 * @param usernameClaim Username claim.
	 * @param additionalScopes Optional additional scopes, or {@code null}.
	 * @param httpConnectTimeout HTTP connect timeout for OP endpoints,
	 * configuration document and JWKS.
	 * @param httpReadTimeout HTTP read timeout for OP endpoints, configuration
	 * document and JWKS.
	 *
	 * @throws IllegalArgumentException If the definition cannot be parsed.
	 *
	 * @deprecated Use JSON-like providers configuration.
	 */
	@Deprecated
	OPDescriptor(
			final String definition,
			final String usernameClaim,
			final String additionalScopes,
			final int httpConnectTimeout,
			final int httpReadTimeout
	) {

		final String[] parts = definition.trim().split("\\s*,\\s*");
		if ((parts.length < 3) || (parts.length > 4))
			throw new IllegalArgumentException(
					"Invalid OP definition: expected 3 or 4 comma-separated" +
						" values.");
		int i = 0;
		this.issuer = parts[i++];
		this.validIssPattern = Pattern.compile("\\Q" + this.issuer + "\\E");
		this.name = this.issuer;
		this.clientId = parts[i++];
		final String secretVal = parts[i++];
		this.clientSecret = (secretVal.length() > 0 ? secretVal : null);
		this.extraAuthEndpointParams = (i < parts.length ? parts[i++] : null);
		this.tokenEndpointAuthMethod = (this.clientSecret != null ?
				TokenEndpointAuthMethod.CLIENT_SECRET_BASIC :
					TokenEndpointAuthMethod.NONE);
		this.usernameClaim = usernameClaim;
		this.usernameClaimParts = this.usernameClaim.split("\\.");
		this.additionalScopes = additionalScopes;
		this.endpointHttpConnectTimeout = httpConnectTimeout;
		this.endpointHttpReadTimeout = httpReadTimeout;
		this.configHttpConnectTimeout = httpConnectTimeout;
		this.configHttpReadTimeout = httpReadTimeout;
		this.jwksHttpConnectTimeout = httpConnectTimeout;
		this.jwksHttpReadTimeout = httpReadTimeout;
		this.optional = false;
		this.configRetryTimeout = 0;

		try {
			this.configUrl = new URL(
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
	 * @param defaultHttpConnectTimeout Default HTTP connect timeout for OP
	 * endpoints, configuration document and JWKS.
	 * @param defaultHttpReadTimeout Default HTTP read timeout for OP
	 * endpoints, configuration document and JWKS.
	 *
	 * @throws IllegalArgumentException If the definition is invalid.
	 */
	OPDescriptor(
			final JSONObject definition,
			final String defaultUsernameClaim,
			final String defaultAdditionalScopes,
			final int defaultHttpConnectTimeout,
			final int defaultHttpReadTimeout
	) {

		this.issuer = definition.optString("issuer", null);
		if (this.issuer == null)
			throw new IllegalArgumentException("Invalid OP definition:"
					+ " missing \"issuer\" property.");
		this.validIssPattern = Pattern.compile(definition.optString("validIssPattern",
				"\\Q" + this.issuer + "\\E"));
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
		this.endpointHttpConnectTimeout = definition.optInt("endpointHttpConnectTimeout",
				defaultHttpConnectTimeout);
		this.endpointHttpReadTimeout = definition.optInt("endpointHttpReadTimeout",
				defaultHttpReadTimeout);
		this.configHttpConnectTimeout = definition.optInt("configHttpConnectTimeout",
				defaultHttpConnectTimeout);
		this.configHttpReadTimeout = definition.optInt("configHttpReadTimeout",
				defaultHttpReadTimeout);
		this.jwksHttpConnectTimeout = definition.optInt("jwksHttpConnectTimeout",
				defaultHttpConnectTimeout);
		this.jwksHttpReadTimeout = definition.optInt("jwkstHttpReadTimeout",
				defaultHttpReadTimeout);
		this.optional = definition.optBoolean("optional");
		this.configRetryTimeout = definition.optInt("configRetryTimeout",
				DEFAULT_CONFIG_RETRY_TIMEOUT);

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
			this.configUrl = new URL(definition.optString(
					"configUrl",
					definition.optString(
							"configurationDocumentUrl", // deprecated option name
							this.issuer + (this.issuer.endsWith("/") ? "" : "/")
								+ ".well-known/openid-configuration")
					)
			);
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
	 * Get pattern used to validate "iss" claim in the ID token.
	 *
	 * @return The "iss" claim validation pattern.
	 */
	Pattern getValidIssPattern() {

		return this.validIssPattern;
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
	URL getConfigUrl() {

		return this.configUrl;
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

	/**
	 * Get HTTP connect timeout for OP endpoints.
	 *
	 * @return The timeout in milliseconds.
	 */
	int getEndpointHttpConnectTimeout() {

		return this.endpointHttpConnectTimeout;
	}

	/**
	 * Get HTTP read timeout for OP endpoints.
	 *
	 * @return The timeout in milliseconds.
	 */
	int getEndpointHttpReadTimeout() {

		return this.endpointHttpReadTimeout;
	}

	/**
	 * Get HTTP connect timeout for OP configuration document URL.
	 *
	 * @return The timeout in milliseconds.
	 */
	int getConfigHttpConnectTimeout() {

		return this.configHttpConnectTimeout;
	}

	/**
	 * Get HTTP read timeout for OP configuration document URL.
	 *
	 * @return The timeout in milliseconds.
	 */
	int getConfigHttpReadTimeout() {

		return this.configHttpReadTimeout;
	}

	/**
	 * Get HTTP connect timeout for OP JWKS URL.
	 *
	 * @return The timeout in milliseconds.
	 */
	int getJwksHttpConnectTimeout() {

		return this.jwksHttpConnectTimeout;
	}

	/**
	 * Get HTTP read timeout for OP JWKS URL.
	 *
	 * @return The timeout in milliseconds.
	 */
	int getJwksHttpReadTimeout() {

		return this.jwksHttpReadTimeout;
	}

	/**
	 * Tell if the OP is optional for the web-application to function. If the
	 * OP is optional, failures to configure it (e.g. fetch the configuration
	 * document) do not prevent the web-application from starting and
	 * functioning, but the OP is made unavailable as if it was never
	 * configured.
	 *
	 * @return {@code true} if OP is optional.
	 */
	boolean isOptional() {

		return this.optional;
	}

	/**
	 * Get configuration retry timeout for optional OP.
	 *
	 * @return The timeout in milliseconds.
	 */
	int getConfigRetryTimeout() {

		return this.configRetryTimeout;
	}
}
