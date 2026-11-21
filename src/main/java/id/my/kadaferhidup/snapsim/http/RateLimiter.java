package id.my.kadaferhidup.snapsim.http;

import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Token bucket per client: {@code burst} requests at once, refilled at {@code perMinute}.
 * Keeps a public demo usable when someone scripts a flood of requests.
 */
public final class RateLimiter {

    private static final int MAX_CLIENTS = 10_000;
    private static final long IDLE_MILLIS = Duration.ofMinutes(10).toMillis();

    private static final class Bucket {
        double tokens;
        long updated;

        Bucket(double tokens, long updated) {
            this.tokens = tokens;
            this.updated = updated;
        }
    }

    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();
    private final Clock clock;
    private final int burst;
    private final double perMilli;

    public RateLimiter(Clock clock, int perMinute, int burst) {
        this(clock, perMinute, Duration.ofMinutes(1), burst);
    }

    /** {@code count} requests per {@code period}, at most {@code burst} at once. */
    public RateLimiter(Clock clock, int count, Duration period, int burst) {
        if (count < 1 || burst < 1 || period.isNegative() || period.isZero()) {
            throw new IllegalArgumentException("Batas harus minimal 1");
        }
        this.clock = clock;
        this.burst = burst;
        this.perMilli = count / (double) period.toMillis();
    }

    /** Takes one token. Returns 0 when allowed, otherwise the seconds to wait. */
    public long acquire(String client) {
        long now = clock.millis();
        if (buckets.size() > MAX_CLIENTS) {
            buckets.values().removeIf(b -> now - b.updated > IDLE_MILLIS);
        }
        Bucket b = buckets.computeIfAbsent(client, k -> new Bucket(burst, now));
        synchronized (b) {
            b.tokens = Math.min(burst, b.tokens + (now - b.updated) * perMilli);
            b.updated = now;
            if (b.tokens >= 1) {
                b.tokens -= 1;
                return 0;
            }
            return Math.max(1, (long) Math.ceil((1 - b.tokens) / perMilli / 1000));
        }
    }

    int clients() {
        return buckets.size();
    }
}
