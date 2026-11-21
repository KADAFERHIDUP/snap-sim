package id.my.kadaferhidup.snapsim.snap;

import id.my.kadaferhidup.snapsim.bank.Bank;
import id.my.kadaferhidup.snapsim.bank.Partner;
import id.my.kadaferhidup.snapsim.json.Json;
import java.time.Clock;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * Checks every SNAP request before the bank sees it. Order matters:
 * headers present → timestamp fresh → token valid and owned by X-PARTNER-ID → signature over the exact
 * body → X-EXTERNAL-ID not seen today. Only a fully verified request can use up an external id.
 */
public final class SnapGateway {

    public static final String TOKEN_SERVICE = "73";
    /** A request signed more than this long ago (or in the future) is refused, which bounds any replay window. */
    public static final Duration MAX_CLOCK_SKEW = Duration.ofMinutes(5);

    private static final Pattern EXTERNAL_ID = Pattern.compile("^[0-9]{1,36}$");
    private static final Pattern CHANNEL_ID = Pattern.compile("^[A-Za-z0-9]{1,5}$");
    private static final Pattern CLIENT_KEY = Pattern.compile("^[A-Za-z0-9_-]{1,64}$");

    private final Bank bank;
    private final TokenStore tokens;
    private final ReplayGuard replay;
    private final Clock clock;

    public SnapGateway(Bank bank, TokenStore tokens, ReplayGuard replay, Clock clock) {
        this.bank = bank;
        this.tokens = tokens;
        this.replay = replay;
        this.clock = clock;
    }

    // ------------------------------------------------------------------ POST /snap/v1.0/access-token/b2b

    public Map<String, Object> issueToken(Function<String, String> header, String rawBody) {
        String ts = required(header, "X-TIMESTAMP");
        String clientKey = required(header, "X-CLIENT-KEY");
        String signature = required(header, "X-SIGNATURE");
        checkTimestamp(ts);
        if (!CLIENT_KEY.matcher(clientKey).matches()) {
            throw SnapException.invalidFormat("X-CLIENT-KEY");
        }
        Map<String, Object> body = parse(rawBody);
        Object grant = body.get("grantType");
        if (grant == null) {
            throw SnapException.missing("grantType");
        }
        if (!"client_credentials".equals(grant)) {
            throw SnapException.invalidFormat("grantType");
        }
        Partner p = bank.partner(clientKey).orElseThrow(() -> SnapException.unauthorized("Unknown client"));
        if (!Signatures.verifyRsa(p.publicKey(), Signatures.tokenStringToSign(clientKey, ts), signature)) {
            throw SnapException.unauthorized("Signature");
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("responseCode", "200" + TOKEN_SERVICE + "00");
        out.put("responseMessage", "Successful");
        out.put("accessToken", tokens.issue(p.clientKey()));
        out.put("tokenType", "Bearer");
        out.put("expiresIn", String.valueOf(TokenStore.TTL.toSeconds()));
        return out;
    }

    // ------------------------------------------------------------------ every transactional endpoint

    /** Verifies a transaction request and returns the partner it belongs to. */
    public Partner authorize(String method, String path, Function<String, String> header, String rawBody) {
        String auth = required(header, "Authorization");
        String ts = required(header, "X-TIMESTAMP");
        String signature = required(header, "X-SIGNATURE");
        String partnerId = required(header, "X-PARTNER-ID");
        String externalId = required(header, "X-EXTERNAL-ID");
        String channel = required(header, "CHANNEL-ID");
        if (!EXTERNAL_ID.matcher(externalId).matches()) {
            throw SnapException.invalidFormat("X-EXTERNAL-ID");
        }
        if (!CHANNEL_ID.matcher(channel).matches()) {
            throw SnapException.invalidFormat("CHANNEL-ID");
        }
        checkTimestamp(ts);
        if (!auth.regionMatches(true, 0, "Bearer ", 0, 7)) {
            throw SnapException.invalidToken();
        }
        String token = auth.substring(7).strip();
        String owner = tokens.partnerOf(token);
        if (!owner.equals(partnerId)) {
            // a token stolen from one partner cannot be used under another partner's id
            throw SnapException.unauthorized("Unknown client");
        }
        Partner p = bank.partner(owner).orElseThrow(() -> SnapException.unauthorized("Unknown client"));
        String stringToSign = Signatures.transactionStringToSign(method, path, token, rawBody, ts);
        if (!Signatures.verifyHmac(p.clientSecret(), stringToSign, signature)) {
            throw SnapException.unauthorized("Signature");
        }
        replay.claim(p.clientKey(), externalId);
        return p;
    }

    // ------------------------------------------------------------------ helpers

    private void checkTimestamp(String ts) {
        OffsetDateTime t;
        try {
            t = OffsetDateTime.parse(ts);
        } catch (DateTimeParseException e) {
            throw SnapException.invalidFormat("X-TIMESTAMP");
        }
        Duration skew = Duration.between(t.toInstant(), clock.instant()).abs();
        if (skew.compareTo(MAX_CLOCK_SKEW) > 0) {
            throw SnapException.unauthorized("Timestamp out of range");
        }
    }

    private static String required(Function<String, String> header, String name) {
        String v = header.apply(name);
        if (v == null || v.isBlank()) {
            throw SnapException.missing(name);
        }
        if (v.length() > 1024) {
            throw SnapException.invalidFormat(name);
        }
        return v.strip();
    }

    public static Map<String, Object> parse(String raw) {
        try {
            return Json.parseObject(raw == null || raw.isBlank() ? "{}" : raw);
        } catch (RuntimeException e) {
            throw SnapException.badRequest();
        }
    }
}
