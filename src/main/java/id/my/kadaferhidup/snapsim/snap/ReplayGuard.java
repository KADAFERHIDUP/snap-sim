package id.my.kadaferhidup.snapsim.snap;

import java.time.Clock;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * X-EXTERNAL-ID must be unique per partner per day. A captured request sent again, even with a valid
 * signature, is refused with 409. Checked only after the signature is verified, so nobody else can
 * use up a partner's ids.
 */
public final class ReplayGuard {

    static final int MAX_PER_PARTNER_PER_DAY = 20_000;

    private final Map<String, Set<String>> seen = new ConcurrentHashMap<>();
    private final Clock clock;
    private final ZoneId zone;
    private volatile LocalDate day;

    public ReplayGuard(Clock clock, ZoneId zone) {
        this.clock = clock;
        this.zone = zone;
    }

    public void claim(String partnerId, String externalId) {
        LocalDate today = LocalDate.now(clock.withZone(zone));
        if (!today.equals(day)) {
            synchronized (this) {
                if (!today.equals(day)) {
                    seen.clear(); // a new day: yesterday's ids no longer matter
                    day = today;
                }
            }
        }
        Set<String> ids = seen.computeIfAbsent(partnerId, k -> ConcurrentHashMap.newKeySet());
        if (ids.size() >= MAX_PER_PARTNER_PER_DAY) {
            throw SnapException.tooManyRequests();
        }
        if (!ids.add(externalId)) {
            throw SnapException.conflict();
        }
    }
}
