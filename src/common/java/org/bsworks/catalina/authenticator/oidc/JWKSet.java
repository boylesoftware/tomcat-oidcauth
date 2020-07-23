package org.bsworks.catalina.authenticator.oidc;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.bsworks.util.json.JSONArray;
import org.bsworks.util.json.JSONObject;

/**
 * JWK set.
 *
 * @author Lev Himmelfarb
 */
class JWKSet {

	/**
	 * ASCII charset.
	 */
	private static final Charset ASCII = Charset.forName("ASCII");


	/**
	 * The keys by key IDs.
	 */
	private final Map<String, PublicKey> keys;


	/**
	 * Construct JWKS from JSON document.
	 *
	 * @param document The JSON document.
	 */
	JWKSet(final JSONObject document) {

		final KeyFactory keyFactory;
		try {
			keyFactory = KeyFactory.getInstance("RSA");
		} catch (final NoSuchAlgorithmException e) {
			throw new RuntimeException("Platform does not support RSA.", e);
		}

		this.keys = new HashMap<>();
		try {
			final JSONArray keysProp = document.getJSONArray("keys");
			final Base64.Decoder base64 = Base64.getUrlDecoder();
			for (int n = keysProp.length() - 1; n >= 0; n--) {
				final JSONObject keyDef = keysProp.getJSONObject(n);
				if (keyDef.optString("kty").equals("RSA")
						&& keyDef.optString("use", "sig").equals("sig"))
					this.keys.put(keyDef.getString("kid"),
							keyFactory.generatePublic(new RSAPublicKeySpec(
									new BigInteger(1, base64.decode(
											keyDef.getString("n").getBytes(
													ASCII))),
									new BigInteger(1, base64.decode(
											keyDef.getString("e").getBytes(
													ASCII))))));
			}
		} catch (final InvalidKeySpecException e) {
			throw new IllegalArgumentException("Invalid key specification.", e);
		}
	}


	/**
	 * Get key.
	 *
	 * @param kid The key ID.
	 *
	 * @return The key.
	 *
	 * @throws IllegalArgumentException If the key ID is unknown.
	 */
	PublicKey getKey(final String kid) {

		final PublicKey key = this.keys.get(kid);
		if (key == null)
			throw new IllegalArgumentException("Unknown key ID: " + kid);

		return key;
	}
}
