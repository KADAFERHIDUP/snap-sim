package id.my.kadaferhidup.snapsim.snap;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HexFormat;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * The two SNAP signatures.
 *
 * <ul>
 *   <li>Asymmetric, for the B2B access token: {@code SHA256withRSA(privateKey, clientKey + "|" + X-TIMESTAMP)},
 *       Base64. The bank only ever holds the partner's public key.</li>
 *   <li>Symmetric, for every transaction: {@code HMAC_SHA512(clientSecret, stringToSign)}, Base64, where
 *       {@code stringToSign = METHOD:path:accessToken:lowercase(hex(SHA-256(minify(body)))):X-TIMESTAMP}.</li>
 * </ul>
 */
public final class Signatures {

    /** RSA keys shorter than this are refused; SNAP asks for at least 2048 bits. */
    public static final int MIN_RSA_BITS = 2048;

    private Signatures() {
    }

    // ------------------------------------------------------------------ asymmetric (access token)

    public static String tokenStringToSign(String clientKey, String timestamp) {
        return clientKey + "|" + timestamp;
    }

    /** Reads a Base64 X.509 SubjectPublicKeyInfo (what WebCrypto exports as "spki"). Also accepts PEM. */
    public static PublicKey parsePublicKey(String text) {
        if (text == null || text.isBlank() || text.length() > 2048) {
            throw SnapException.invalidFormat("publicKey");
        }
        String b64 = text.replaceAll("-----(BEGIN|END) PUBLIC KEY-----", "").replaceAll("\\s", "");
        try {
            PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(b64)));
            if (((RSAPublicKey) key).getModulus().bitLength() < MIN_RSA_BITS) {
                throw new SnapException(400, "01", "Invalid Field Format publicKey (RSA minimal " + MIN_RSA_BITS + " bit)");
            }
            return key;
        } catch (IllegalArgumentException | GeneralSecurityException | ClassCastException e) {
            throw SnapException.invalidFormat("publicKey");
        }
    }

    public static boolean verifyRsa(PublicKey key, String stringToSign, String signatureB64) {
        try {
            Signature s = Signature.getInstance("SHA256withRSA");
            s.initVerify(key);
            s.update(stringToSign.getBytes(StandardCharsets.UTF_8));
            return s.verify(Base64.getDecoder().decode(signatureB64.strip()));
        } catch (IllegalArgumentException | GeneralSecurityException e) {
            return false;
        }
    }

    /** Partner side, used by tests and by anyone reading this file to see the exact format. */
    public static String signRsa(PrivateKey key, String stringToSign) throws GeneralSecurityException {
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(key);
        s.update(stringToSign.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(s.sign());
    }

    // ------------------------------------------------------------------ symmetric (transactions)

    public static String transactionStringToSign(String method, String path, String accessToken, String rawBody,
                                                 String timestamp) {
        return method.toUpperCase() + ":" + path + ":" + accessToken + ":" + bodyHash(rawBody) + ":" + timestamp;
    }

    public static String bodyHash(String rawBody) {
        try {
            byte[] h = MessageDigest.getInstance("SHA-256").digest(minify(rawBody).getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(h); // lowercase
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String hmacSha512(String secret, String stringToSign) {
        try {
            Mac mac = Mac.getInstance("HmacSHA512");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA512"));
            return Base64.getEncoder().encodeToString(mac.doFinal(stringToSign.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Constant-time comparison of the decoded signatures, so timing does not reveal how many bytes matched. */
    public static boolean verifyHmac(String secret, String stringToSign, String signatureB64) {
        try {
            byte[] expected = Base64.getDecoder().decode(hmacSha512(secret, stringToSign));
            byte[] given = Base64.getDecoder().decode(signatureB64.strip());
            return MessageDigest.isEqual(expected, given);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * Removes whitespace outside string literals, keeping key order and the exact text of every value.
     * Re-serialising the JSON instead would change number formatting and break the partner's hash.
     */
    public static String minify(String json) {
        if (json == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(json.length());
        boolean inString = false;
        boolean escaped = false;
        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);
            if (inString) {
                sb.append(c);
                if (escaped) {
                    escaped = false;
                } else if (c == '\\') {
                    escaped = true;
                } else if (c == '"') {
                    inString = false;
                }
            } else if (c == '"') {
                inString = true;
                sb.append(c);
            } else if (c != ' ' && c != '\n' && c != '\r' && c != '\t') {
                sb.append(c);
            }
        }
        return sb.toString();
    }
}
