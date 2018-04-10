package org.bsworks.catalina.authenticator.oidc;


/**
 * OP's token endpoint authentication method.
 *
 * @author Lev Himmelfarb
 */
enum TokenEndpointAuthMethod {

	/**
	 * HTTP Basic authentication with client secret as the password.
	 */
	CLIENT_SECRET_BASIC,

	/**
	 * Client secret in the {@code POST} body.
	 */
	CLIENT_SECRET_POST,

	/**
	 * Currently not supported.
	 */
	CLIENT_SECRET_JWT,

	/**
	 * Currently not supported.
	 */
	PRIVATE_KEY_JWT,

	/**
	 * No authentication.
	 */
	NONE
}
