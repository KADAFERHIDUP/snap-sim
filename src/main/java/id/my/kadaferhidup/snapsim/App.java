package id.my.kadaferhidup.snapsim;

import com.sun.net.httpserver.HttpServer;
import id.my.kadaferhidup.snapsim.bank.Bank;
import id.my.kadaferhidup.snapsim.http.Api;
import id.my.kadaferhidup.snapsim.http.RateLimiter;
import id.my.kadaferhidup.snapsim.snap.ReplayGuard;
import id.my.kadaferhidup.snapsim.snap.SnapGateway;
import id.my.kadaferhidup.snapsim.snap.SnapServices;
import id.my.kadaferhidup.snapsim.snap.TokenStore;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.time.Clock;
import java.time.Duration;
import java.util.concurrent.Executors;
import java.util.logging.Logger;

/** Wires the simulator together and starts the HTTP server. */
public final class App implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(App.class.getName());

    /** Settings from environment variables. */
    public record Config(int port, int snapPerMinute, int sandboxesPerHour) {

        public static Config fromEnv() {
            return new Config(intEnv("PORT", 8080), intEnv("SNAP_RATE_LIMIT_PER_MINUTE", 120), intEnv("SANDBOX_PER_HOUR", 10));
        }

        private static int intEnv(String name, int fallback) {
            String v = System.getenv(name);
            return v == null || v.isBlank() ? fallback : Integer.parseInt(v.strip());
        }
    }

    private final HttpServer server;
    private final Bank bank;

    private App(HttpServer server, Bank bank) {
        this.server = server;
        this.bank = bank;
    }

    public static App start(Config cfg, Clock clock) throws IOException {
        Bank bank = new Bank(clock);
        TokenStore tokens = new TokenStore(clock);
        SnapGateway gateway = new SnapGateway(bank, tokens, new ReplayGuard(clock, Bank.ZONE), clock);
        Api api = new Api(bank, gateway, new SnapServices(bank, clock),
                new RateLimiter(clock, cfg.snapPerMinute(), Math.max(10, cfg.snapPerMinute() / 4)),
                new RateLimiter(clock, cfg.sandboxesPerHour(), Duration.ofHours(1), Math.min(3, cfg.sandboxesPerHour())),
                clock);
        HttpServer server = HttpServer.create(new InetSocketAddress(cfg.port()), 128);
        server.createContext("/", api);
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        server.start();
        return new App(server, bank);
    }

    public int port() {
        return server.getAddress().getPort();
    }

    public Bank bank() {
        return bank;
    }

    @Override
    public void close() {
        server.stop(0);
    }

    public static void main(String[] args) throws IOException {
        App app = start(Config.fromEnv(), Clock.systemUTC());
        LOG.info("snap-sim jalan di port " + app.port());
    }
}
