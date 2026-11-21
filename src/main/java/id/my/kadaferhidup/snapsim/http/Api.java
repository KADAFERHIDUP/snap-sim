package id.my.kadaferhidup.snapsim.http;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import id.my.kadaferhidup.snapsim.bank.Account;
import id.my.kadaferhidup.snapsim.bank.Bank;
import id.my.kadaferhidup.snapsim.bank.Partner;
import id.my.kadaferhidup.snapsim.json.Json;
import id.my.kadaferhidup.snapsim.snap.SnapException;
import id.my.kadaferhidup.snapsim.snap.SnapGateway;
import id.my.kadaferhidup.snapsim.snap.SnapServices;
import id.my.kadaferhidup.snapsim.snap.Signatures;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.logging.Level;
import java.util.logging.Logger;

/** Routes HTTP requests to the sandbox, the SNAP gateway and the web console. */
public final class Api implements HttpHandler {

    private static final Logger LOG = Logger.getLogger(Api.class.getName());
    private static final int MAX_BODY = 8 * 1024;
    public static final String PREFIX = "/snap/v1.0";

    private record Service(String code, BiFunction<Partner, Map<String, Object>, Map<String, Object>> run) {
    }

    private final Bank bank;
    private final SnapGateway gateway;
    private final Map<String, Service> services;
    private final RateLimiter snapLimit;
    private final RateLimiter sandboxLimit;
    private final StaticFiles files = new StaticFiles();
    private final Clock clock;

    public Api(Bank bank, SnapGateway gateway, SnapServices svc, RateLimiter snapLimit, RateLimiter sandboxLimit, Clock clock) {
        this.bank = bank;
        this.gateway = gateway;
        this.snapLimit = snapLimit;
        this.sandboxLimit = sandboxLimit;
        this.clock = clock;
        this.services = Map.of(
                PREFIX + "/balance-inquiry", new Service(SnapServices.BALANCE, svc::balance),
                PREFIX + "/account-inquiry-internal", new Service(SnapServices.ACCOUNT_INQUIRY_INTERNAL, svc::accountInquiry),
                PREFIX + "/transfer-intrabank", new Service(SnapServices.TRANSFER_INTRABANK, svc::transfer),
                PREFIX + "/transfer/status", new Service(SnapServices.TRANSFER_STATUS, svc::status));
    }

    @Override
    public void handle(HttpExchange ex) throws IOException {
        try (ex) {
            securityHeaders(ex);
            String path = ex.getRequestURI().getRawPath();
            String method = ex.getRequestMethod();
            if (path.equals("/api/health")) {
                json(ex, 200, Map.of("status", "ok"));
            } else if (path.equals("/sandbox/partners")) {
                sandbox(ex);
            } else if (path.equals(PREFIX + "/access-token/b2b")) {
                snap(ex, SnapGateway.TOKEN_SERVICE, () -> gateway.issueToken(h -> ex.getRequestHeaders().getFirst(h), readJsonBody(ex)));
            } else if (services.containsKey(path)) {
                Service s = services.get(path);
                snap(ex, s.code(), () -> {
                    String raw = readJsonBody(ex);
                    Partner p = gateway.authorize(method, path, h -> ex.getRequestHeaders().getFirst(h), raw);
                    return s.run().apply(p, SnapGateway.parse(raw));
                });
            } else if (method.equals("GET") || method.equals("HEAD")) {
                files.serve(ex, path);
            } else {
                json(ex, 404, Map.of("responseCode", "4040000", "responseMessage", "Not Found"));
            }
        } catch (RuntimeException e) {
            LOG.log(Level.WARNING, "permintaan gagal", e);
        }
    }

    // ------------------------------------------------------------------ SNAP envelope

    private interface Call {
        Map<String, Object> run();
    }

    private void snap(HttpExchange ex, String service, Call call) throws IOException {
        ex.getResponseHeaders().set("X-TIMESTAMP",
                OffsetDateTime.now(clock.withZone(Bank.ZONE)).truncatedTo(ChronoUnit.SECONDS).toString());
        try {
            if (!ex.getRequestMethod().equals("POST")) {
                throw new SnapException(405, "00", "Method Not Allowed");
            }
            if (snapLimit.acquire(Http.clientIp(ex)) > 0) {
                throw SnapException.tooManyRequests();
            }
            json(ex, 200, call.run());
        } catch (SnapException e) {
            json(ex, e.http(), Map.of("responseCode", e.code(service), "responseMessage", e.getMessage()));
        } catch (RuntimeException e) {
            // never echo internals to the caller; the log keeps the detail
            LOG.log(Level.SEVERE, "kesalahan tak terduga", e);
            SnapException g = SnapException.general();
            json(ex, 500, Map.of("responseCode", g.code(service), "responseMessage", g.getMessage()));
        }
    }

    // ------------------------------------------------------------------ sandbox

    private void sandbox(HttpExchange ex) throws IOException {
        try {
            requirePost(ex);
            long wait = sandboxLimit.acquire(Http.clientIp(ex));
            if (wait > 0) {
                ex.getResponseHeaders().set("Retry-After", String.valueOf(wait));
                json(ex, 429, Map.of("error", "Terlalu banyak sandbox dari alamat ini. Coba lagi " + wait + " detik lagi."));
                return;
            }
            Map<String, Object> body = SnapGateway.parse(readJsonBody(ex));
            Object pk = body.get("publicKey");
            Bank.Sandbox sb = bank.createSandbox(Signatures.parsePublicKey(pk instanceof String s ? s : null));
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("clientKey", sb.partner().clientKey());
            out.put("clientSecret", sb.partner().clientSecret());
            out.put("accounts", sb.accounts().stream().map(a -> Map.of("accountNo", a.no(), "name", a.name(),
                    "balance", SnapServices.money(a.balance()))).toList());
            out.put("beneficiaries", List.of(
                    Map.of("accountNo", Bank.SHARED_ACTIVE_1, "name", Account.mask(Bank.OWNER), "status", "ACTIVE"),
                    Map.of("accountNo", Bank.SHARED_ACTIVE_2, "name", Account.mask(Bank.OWNER), "status", "ACTIVE"),
                    Map.of("accountNo", Bank.SHARED_DORMANT, "name", Account.mask(Bank.OWNER), "status", "DORMANT")));
            out.put("expiresAt", sb.partner().createdAt().plus(java.time.Duration.ofHours(24)).toString());
            ex.getResponseHeaders().set("Cache-Control", "no-store");
            json(ex, 201, out);
        } catch (SnapException e) {
            json(ex, e.http(), Map.of("error", e.getMessage()));
        }
    }

    // ------------------------------------------------------------------ plumbing

    private static void requirePost(HttpExchange ex) {
        if (!ex.getRequestMethod().equals("POST")) {
            throw new SnapException(405, "00", "Method Not Allowed");
        }
    }

    private static String readJsonBody(HttpExchange ex) {
        String type = ex.getRequestHeaders().getFirst("Content-Type");
        if (type == null || !type.toLowerCase().startsWith("application/json")) {
            throw SnapException.missing("Content-Type");
        }
        try (InputStream in = ex.getRequestBody()) {
            byte[] b = in.readNBytes(MAX_BODY + 1);
            if (b.length > MAX_BODY) {
                throw SnapException.badRequest();
            }
            return new String(b, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw SnapException.badRequest();
        }
    }

    static void json(HttpExchange ex, int status, Object value) throws IOException {
        byte[] out = Json.write(value).getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.getResponseHeaders().set("Cache-Control", "no-store");
        boolean head = ex.getRequestMethod().equals("HEAD");
        ex.sendResponseHeaders(status, head ? -1 : out.length);
        if (!head) {
            ex.getResponseBody().write(out);
        }
    }

    private static void securityHeaders(HttpExchange ex) {
        var h = ex.getResponseHeaders();
        h.set("X-Content-Type-Options", "nosniff");
        h.set("Referrer-Policy", "no-referrer");
        h.set("X-Frame-Options", "DENY");
        h.set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; "
                + "font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
                + "base-uri 'none'; form-action 'none'");
    }
}
