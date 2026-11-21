package id.my.kadaferhidup.snapsim;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import id.my.kadaferhidup.snapsim.bank.Bank;
import id.my.kadaferhidup.snapsim.json.Json;
import id.my.kadaferhidup.snapsim.snap.Signatures;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** The real server on a random port, called the way a partner would call it. */
class AppTest {

    static final String SNAP = "/snap/v1.0";
    static final AtomicLong EXT = new AtomicLong(1_000_000);

    MutableClock clock;
    App app;
    HttpClient http = HttpClient.newHttpClient();

    record Res(int status, Map<String, Object> body) {
        String code() {
            return String.valueOf(body.get("responseCode"));
        }
    }

    /** A partner as the bank sees it after sandbox registration, plus the private key only it holds. */
    final class Client {
        final KeyPair keys;
        final String clientKey;
        final String secret;
        final List<String> accounts = new ArrayList<>();
        String token;

        @SuppressWarnings("unchecked")
        Client() throws Exception {
            KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
            g.initialize(2048);
            keys = g.generateKeyPair();
            Res r = post("/sandbox/partners", "{\"publicKey\":\"" + Base64.getEncoder().encodeToString(keys.getPublic().getEncoded()) + "\"}", Map.of());
            assertEquals(201, r.status(), String.valueOf(r.body()));
            clientKey = (String) r.body().get("clientKey");
            secret = (String) r.body().get("clientSecret");
            for (Object o : (List<Object>) r.body().get("accounts")) {
                accounts.add((String) ((Map<String, Object>) o).get("accountNo"));
            }
        }

        Res token() throws Exception {
            String ts = ts();
            Res r = post(SNAP + "/access-token/b2b", "{\"grantType\":\"client_credentials\"}", Map.of(
                    "X-TIMESTAMP", ts, "X-CLIENT-KEY", clientKey,
                    "X-SIGNATURE", Signatures.signRsa(keys.getPrivate(), Signatures.tokenStringToSign(clientKey, ts))));
            if (r.status() == 200) {
                token = (String) r.body().get("accessToken");
            }
            return r;
        }

        Res call(String path, String body) throws Exception {
            return call(path, body, String.valueOf(EXT.incrementAndGet()), body);
        }

        /** {@code signedBody} is what gets signed, {@code body} what gets sent: different means tampering. */
        Res call(String path, String body, String externalId, String signedBody) throws Exception {
            String ts = ts();
            String sig = Signatures.hmacSha512(secret, Signatures.transactionStringToSign("POST", SNAP + path, token, signedBody, ts));
            return post(SNAP + path, body, Map.of("Authorization", "Bearer " + token, "X-TIMESTAMP", ts, "X-SIGNATURE", sig,
                    "X-PARTNER-ID", clientKey, "X-EXTERNAL-ID", externalId, "CHANNEL-ID", "95221"));
        }
    }

    @BeforeEach
    void start() throws Exception {
        clock = new MutableClock(Instant.now());
        app = App.start(new App.Config(0, 1000, 1000), clock);
    }

    @AfterEach
    void stop() {
        app.close();
    }

    String ts() {
        return OffsetDateTime.ofInstant(clock.instant(), Bank.ZONE).withNano(0).toString();
    }

    Res post(String path, String body, Map<String, String> headers) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("http://localhost:" + app.port() + path))
                .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body));
        headers.forEach(b::header);
        HttpResponse<String> r = http.send(b.build(), HttpResponse.BodyHandlers.ofString());
        return new Res(r.statusCode(), Json.parseObject(r.body()));
    }

    static String transfer(String ref, String from, String to, String value) {
        return "{\"partnerReferenceNo\":\"" + ref + "\",\"amount\":{\"value\":\"" + value + "\",\"currency\":\"IDR\"},"
                + "\"beneficiaryAccountNo\":\"" + to + "\",\"sourceAccountNo\":\"" + from + "\",\"remark\":\"Uji\"}";
    }

    // ------------------------------------------------------------------ the happy path

    @Test
    @SuppressWarnings("unchecked")
    void fullFlowTokenBalanceInquiryTransferStatus() throws Exception {
        Client c = new Client();
        Res t = c.token();
        assertEquals("2007300", t.code());
        assertEquals("900", t.body().get("expiresIn"));

        Res bal = c.call("/balance-inquiry", "{\"partnerReferenceNo\":\"B1\",\"accountNo\":\"" + c.accounts.get(0) + "\"}");
        assertEquals("2001100", bal.code());
        Map<String, Object> info = ((List<Map<String, Object>>) bal.body().get("accountInfos")).get(0);
        assertEquals("25000000.00", ((Map<String, Object>) info.get("availableBalance")).get("value"));

        Res inq = c.call("/account-inquiry-internal", "{\"partnerReferenceNo\":\"I1\",\"beneficiaryAccountNo\":\"" + Bank.SHARED_ACTIVE_1 + "\"}");
        assertEquals("2001500", inq.code());
        assertEquals("Ah*** Um******", inq.body().get("beneficiaryAccountName"));

        Res tr = c.call("/transfer-intrabank", transfer("TRX-1", c.accounts.get(0), Bank.SHARED_ACTIVE_1, "150000.00"));
        assertEquals("2001700", tr.code(), String.valueOf(tr.body()));
        assertNotNull(tr.body().get("referenceNo"));

        Res st = c.call("/transfer/status", "{\"originalPartnerReferenceNo\":\"TRX-1\",\"serviceCode\":\"17\"}");
        assertEquals("2003600", st.code());
        assertEquals("00", st.body().get("latestTransactionStatus"));
        assertEquals(tr.body().get("referenceNo"), st.body().get("originalReferenceNo"));

        assertEquals(25_000_000_00L - 150_000_00L, app.bank().owned(c.clientKey, c.accounts.get(0)).balance());
        assertTrue(app.bank().balanced());
    }

    @Test
    void prettyPrintedBodyVerifiesBecauseTheHashIsOverTheMinifiedBody() throws Exception {
        Client c = new Client();
        c.token();
        String pretty = "{\n  \"partnerReferenceNo\": \"B1\",\n  \"accountNo\": \"" + c.accounts.get(0) + "\"\n}";
        assertEquals("2001100", c.call("/balance-inquiry", pretty).code());
    }

    // ------------------------------------------------------------------ attacks that must fail

    @Test
    void tamperedBodyIsRefused() throws Exception {
        Client c = new Client();
        c.token();
        String signed = transfer("T1", c.accounts.get(0), Bank.SHARED_ACTIVE_1, "10.00");
        String sent = transfer("T1", c.accounts.get(0), Bank.SHARED_ACTIVE_1, "10000000.00");
        Res r = c.call("/transfer-intrabank", sent, String.valueOf(EXT.incrementAndGet()), signed);
        assertEquals(401, r.status());
        assertEquals("4011700", r.code());
        assertEquals(25_000_000_00L, app.bank().owned(c.clientKey, c.accounts.get(0)).balance());
    }

    @Test
    void replayedExternalIdIsRefused() throws Exception {
        Client c = new Client();
        c.token();
        String body = "{\"partnerReferenceNo\":\"B1\",\"accountNo\":\"" + c.accounts.get(0) + "\"}";
        assertEquals("2001100", c.call("/balance-inquiry", body, "42", body).code());
        Res again = c.call("/balance-inquiry", body, "42", body);
        assertEquals(409, again.status());
        assertEquals("4091100", again.code());
    }

    @Test
    void retriedTransferDebitsOnceAndAChangedOneIsRefused() throws Exception {
        Client c = new Client();
        c.token();
        String body = transfer("ONCE", c.accounts.get(0), Bank.SHARED_ACTIVE_2, "1000000.00");
        Res a = c.call("/transfer-intrabank", body);
        Res b = c.call("/transfer-intrabank", body); // new external id, same partnerReferenceNo: a network retry
        assertEquals("2001700", b.code());
        assertEquals(a.body().get("referenceNo"), b.body().get("referenceNo"));
        assertEquals(24_000_000_00L, app.bank().owned(c.clientKey, c.accounts.get(0)).balance());
        Res changed = c.call("/transfer-intrabank", transfer("ONCE", c.accounts.get(0), Bank.SHARED_ACTIVE_2, "2000000.00"));
        assertEquals("4091701", changed.code());
    }

    @Test
    void wrongRsaKeyGetsNoToken() throws Exception {
        Client c = new Client();
        Client other = new Client();
        String ts = ts();
        Res r = post(SNAP + "/access-token/b2b", "{\"grantType\":\"client_credentials\"}", Map.of("X-TIMESTAMP", ts,
                "X-CLIENT-KEY", c.clientKey, "X-SIGNATURE", Signatures.signRsa(other.keys.getPrivate(), c.clientKey + "|" + ts)));
        assertEquals("4017300", r.code());
        assertFalse(r.body().containsKey("accessToken"));
    }

    @Test
    void oneSandboxCannotTouchAnothersAccountsOrTransfers() throws Exception {
        Client victim = new Client();
        Client thief = new Client();
        victim.token();
        thief.token();
        victim.call("/transfer-intrabank", transfer("V1", victim.accounts.get(0), Bank.SHARED_ACTIVE_1, "100.00"));

        assertEquals("4041111", thief.call("/balance-inquiry", "{\"accountNo\":\"" + victim.accounts.get(0) + "\"}").code());
        assertEquals("4041711", thief.call("/transfer-intrabank",
                transfer("STEAL", victim.accounts.get(0), thief.accounts.get(0), "1000000.00")).code());
        assertEquals("4043601", thief.call("/transfer/status", "{\"originalPartnerReferenceNo\":\"V1\",\"serviceCode\":\"17\"}").code());

        // the thief's own token under the victim's partner id
        String saved = thief.token;
        Client masquerade = victim;
        String victimToken = masquerade.token;
        masquerade.token = saved;
        assertEquals("4011100", masquerade.call("/balance-inquiry", "{\"accountNo\":\"" + victim.accounts.get(0) + "\"}").code());
        masquerade.token = victimToken;

        assertEquals(25_000_000_00L - 100_00L, app.bank().owned(victim.clientKey, victim.accounts.get(0)).balance());
    }

    @Test
    void expiredTokenAndStaleTimestampAreRefused() throws Exception {
        Client c = new Client();
        c.token();
        String body = "{\"accountNo\":\"" + c.accounts.get(0) + "\"}";
        clock.advance(Duration.ofSeconds(901));
        assertEquals("4011101", c.call("/balance-inquiry", body).code());

        c.token();
        String old = ts();
        clock.advance(Duration.ofMinutes(6));
        String sig = Signatures.hmacSha512(c.secret, Signatures.transactionStringToSign("POST", SNAP + "/balance-inquiry", c.token, body, old));
        Res r = post(SNAP + "/balance-inquiry", body, Map.of("Authorization", "Bearer " + c.token, "X-TIMESTAMP", old,
                "X-SIGNATURE", sig, "X-PARTNER-ID", c.clientKey, "X-EXTERNAL-ID", "77", "CHANNEL-ID", "95221"));
        assertEquals("4011100", r.code(), "tanda tangan sah tapi lebih dari 5 menit lalu");
    }

    @Test
    void missingHeadersAndBadFieldsGetTheirCodes() throws Exception {
        Client c = new Client();
        c.token();
        Res r = post(SNAP + "/balance-inquiry", "{}", Map.of("X-TIMESTAMP", ts()));
        assertEquals("4001102", r.code());
        assertEquals("Invalid Mandatory Field Authorization", r.body().get("responseMessage"));
        assertEquals("4001702", c.call("/transfer-intrabank", "{\"partnerReferenceNo\":\"X\"}").code());
        assertEquals("4001701", c.call("/transfer-intrabank", transfer("X2", c.accounts.get(0), Bank.SHARED_ACTIVE_1, "10.5")).code(),
                "nominal wajib dua desimal");
        assertEquals("4001701", c.call("/transfer-intrabank", transfer("X3", c.accounts.get(0), Bank.SHARED_ACTIVE_1, "-5.00")).code());
        assertEquals("4031718", c.call("/transfer-intrabank", transfer("X4", c.accounts.get(0), Bank.SHARED_DORMANT, "5.00")).code());
    }

    @Test
    void weakOrBrokenPublicKeysCannotRegister() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(1024);
        String weak = Base64.getEncoder().encodeToString(g.generateKeyPair().getPublic().getEncoded());
        assertEquals(400, post("/sandbox/partners", "{\"publicKey\":\"" + weak + "\"}", Map.of()).status());
        assertEquals(400, post("/sandbox/partners", "{\"publicKey\":\"abc\"}", Map.of()).status());
    }

    @Test
    void sandboxCreationIsRateLimitedPerIp() throws Exception {
        app.close();
        app = App.start(new App.Config(0, 1000, 2), clock);
        new Client();
        new Client();
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        String pk = Base64.getEncoder().encodeToString(g.generateKeyPair().getPublic().getEncoded());
        assertEquals(429, post("/sandbox/partners", "{\"publicKey\":\"" + pk + "\"}", Map.of()).status());
    }
}
