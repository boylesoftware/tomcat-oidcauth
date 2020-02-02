package org.bsworks.catalina.authenticator.oidc.tomcat85;

import java.io.IOException;
import java.util.stream.Stream;

import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.connector.Request;
import org.apache.catalina.util.ServerInfo;
import org.bsworks.catalina.authenticator.oidc.BaseOpenIDConnectAuthenticator;


/**
 * <em>OpenID Connect</em> authenticator implementation for <em>Tomcat 8.5</em>.
 *
 * @author Lev Himmelfarb
 */
public class OpenIDConnectAuthenticator
	extends BaseOpenIDConnectAuthenticator {

	@Override
	protected void ensureTomcatVersion()
		throws LifecycleException {

		final Integer[] versionParts = Stream.of(ServerInfo.getServerNumber().split("\\."))
			.map(v -> Integer.parseInt(v))
			.toArray(Integer[]::new);
		if ((versionParts[0].intValue() != 8)
				|| (versionParts[1].intValue() != 5)
				|| (versionParts[2].intValue() < 50))
			throw new LifecycleException("OpenIDConnectAuthenticator requires"
				+ " Apache Tomcat 8.5 version 8.5.50 or higher.");
	}

	@Override
	protected boolean doAuthenticate(final Request request,
			final HttpServletResponse response)
		throws IOException {

		return this.performAuthentication(request, response);
	}
}
