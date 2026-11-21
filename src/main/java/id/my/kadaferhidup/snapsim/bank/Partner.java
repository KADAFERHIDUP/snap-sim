package id.my.kadaferhidup.snapsim.bank;

import java.security.PublicKey;
import java.time.Instant;

/**
 * A partner (PJP or merchant) connected to the bank. The bank holds the partner's RSA <em>public</em> key only;
 * the private key never leaves the partner. {@code clientSecret} is the shared HMAC key for transactions.
 */
public record Partner(String clientKey, String clientSecret, PublicKey publicKey, Instant createdAt) {

    @Override
    public String toString() {
        return "Partner[" + clientKey + "]"; // never print the secret into a log
    }
}
