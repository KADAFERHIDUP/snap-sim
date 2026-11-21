package id.my.kadaferhidup.snapsim.snap;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * B2B access tokens: 256 random bits, valid 900 seconds, bound to one partner.
 * Only the SHA-256 of a token is kept, so a memory dump does not hand out working tokens.
 */
public final class TokenStore {

    public static final Duration TTL = Duration.ofSeconds(900);
    static final int MAX_TOKENS = 50_000;

    private record Grant(String partnerId, Instant expiresAt) {
    }

    private final Map<String, Grant> grants = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();
    private final Clock clock;

    public TokenStore(Clock clock) {
        this.clock = clock;
    }

    public String issue(String partnerId) {
        Instant now = clock.instant();
        if (grants.size() >= MAX_TOKENS) {
            grants.values().removeIf(g -> !g.expiresAt().isAfter(now));
            if (grants.size() >= MAX_TOKENS) {
                throw SnapException.tooManyRequests();
            }
        }
        byte[] b = new byte[32];
        random.nextBytes(b);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(b);
        grants.put(hash(token), new Grant(partnerId, now.plus(TTL)));
        return token;
    }

    /** The partner this token belongs to; an unknown or expired token is refused. */
    public String partnerOf(String token) {
        if (token == null || token.length() < 20 || token.length() > 200) {
            throw SnapException.invalidToken();
        }
        String h = hash(token);
        Grant g = grants.get(h);
        if (g == null) {
            throw SnapException.invalidToken();
        }
        if (!g.expiresAt().isAfter(clock.instant())) {
            grants.remove(h);
            throw SnapException.invalidToken();
        }
        return g.partnerId();
    }

    private static String hash(String token) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
