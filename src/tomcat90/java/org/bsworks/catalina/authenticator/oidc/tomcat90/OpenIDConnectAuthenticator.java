package org.bsworks.catalina.authenticator.oidc.tomcat90;

import java.io.IOException;

import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.connector.Request;
import org.bsworks.catalina.authenticator.oidc.BaseOpenIDConnectAuthenticator;


/**
 * <em>OpenID Connect</em> authenticator implementation for <em>Tomcat 9.0</em>.
 *
 * @author Lev Himmelfarb
 */
public class OpenIDConnectAuthenticator
	extends BaseOpenIDConnectAuthenticator {

	/* (non-Javadoc)
	 * @see org.apache.catalina.authenticator.FormAuthenticator#doAuthenticate(org.apache.catalina.connector.Request, javax.servlet.http.HttpServletResponse)
	 */
	@Override
	protected boolean doAuthenticate(final Request request,
			final HttpServletResponse response)
		throws IOException {

		return this.performAuthentication(request, response);
	}
}
