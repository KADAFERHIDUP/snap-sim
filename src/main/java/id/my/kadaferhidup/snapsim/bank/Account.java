package id.my.kadaferhidup.snapsim.bank;

import java.time.LocalDate;
import java.util.concurrent.locks.ReentrantLock;

/**
 * A rupiah account. Money is kept in sen (1/100 rupiah) as a {@code long}, never as a floating point number.
 * The balance and the day's outgoing total only change while {@link #lock} is held.
 */
public final class Account {

    public enum Status { ACTIVE, DORMANT }

    private final String no;
    private final String name;
    private final String ownerPartnerId;
    private final Status status;
    final ReentrantLock lock = new ReentrantLock();

    private long balance;
    private LocalDate outDay;
    private long outToday;

    Account(String no, String name, String ownerPartnerId, Status status, long balance) {
        this.no = no;
        this.name = name;
        this.ownerPartnerId = ownerPartnerId;
        this.status = status;
        this.balance = balance;
    }

    public String no() {
        return no;
    }

    public String name() {
        return name;
    }

    public Status status() {
        return status;
    }

    public boolean ownedBy(String partnerId) {
        return ownerPartnerId != null && ownerPartnerId.equals(partnerId);
    }

    String ownerPartnerId() {
        return ownerPartnerId;
    }

    public long balance() {
        lock.lock();
        try {
            return balance;
        } finally {
            lock.unlock();
        }
    }

    // ------------------------------------------------------------------ called by Bank with the lock held

    long outgoingOn(LocalDate day) {
        return day.equals(outDay) ? outToday : 0;
    }

    void debit(long amount, LocalDate day) {
        if (amount <= 0 || amount > balance) {
            throw new IllegalStateException("debit tidak valid");
        }
        balance -= amount;
        if (!day.equals(outDay)) {
            outDay = day;
            outToday = 0;
        }
        outToday += amount;
    }

    void credit(long amount) {
        if (amount <= 0) {
            throw new IllegalStateException("kredit tidak valid");
        }
        balance = Math.addExact(balance, amount);
    }

    long balanceLocked() {
        return balance;
    }

    /** "Ahmad Umraithi" becomes "Ah*** Um*******": enough to confirm the payee, not enough to harvest names. */
    public static String mask(String name) {
        StringBuilder sb = new StringBuilder();
        for (String w : name.trim().split("\\s+")) {
            if (!sb.isEmpty()) {
                sb.append(' ');
            }
            int keep = Math.min(2, w.length());
            sb.append(w, 0, keep).append("*".repeat(w.length() - keep));
        }
        return sb.toString();
    }
}
