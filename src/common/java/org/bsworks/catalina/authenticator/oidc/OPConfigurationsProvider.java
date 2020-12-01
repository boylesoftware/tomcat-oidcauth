package org.bsworks.catalina.authenticator.oidc;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.bsworks.util.json.JSONObject;


/**
 * Provider of the OpenID Provider (OP) configurations. The provider is
 * responsible for loading, parsing and caching the OP configuration documents.
 *
 * @author Lev Himmelfarb
 */
class OPConfigurationsProvider {

	/**
	 * Configuration providers by issuer IDs.
	 */
	private final Map<String, ConfigProvider<OPConfiguration>> providers;


	/**
	 * Create new provider.
	 *
	 * @param opDescs Descriptors of supported OPs.
	 */
	OPConfigurationsProvider(final Iterable<OPDescriptor> opDescs) {

		this.providers = new HashMap<>();
		for (final OPDescriptor opDesc : opDescs)
			if (this.providers.put(opDesc.getIssuer(),
					new ConfigProvider<OPConfiguration>(
							opDesc.getConfigUrl(),
							opDesc.getConfigHttpConnectTimeout(),
							opDesc.getConfigHttpReadTimeout(),
							opDesc.isOptional(),
							opDesc.getConfigRetryTimeout()
					) {
						@Override
						protected OPConfiguration parseDocument(
								final JSONObject document) throws IOException {
							return new OPConfiguration(
									document,
									opDesc.getJwksHttpConnectTimeout(),
									opDesc.getJwksHttpReadTimeout()
							);
						}
					}) != null)
				throw new IllegalArgumentException(
					"Issuer ID " + opDesc.getIssuer() +
						" is used for more than one OP.");
	}


	/**
	 * Get OP configuration.
	 *
	 * @param issuer The OP's issuer ID.
	 *
	 * @return The configuration, or {@code null} if the OP is optional and
	 * there was an error loading the OP configuration document.
	 *
	 * @throws IllegalArgumentException If the issuer ID is unknown.
	 * @throws IOException If an I/O error happens loading the OP configuration
	 * document.
	 */
	OPConfiguration getOPConfiguration(final String issuer)
		throws IOException {

		final ConfigProvider<OPConfiguration> provider =
			this.providers.get(issuer);
		if (provider == null)
			throw new IllegalArgumentException("Unknown issuer ID: " + issuer);

		return provider.get();
	}
}
