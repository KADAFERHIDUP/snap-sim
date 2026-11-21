package id.my.kadaferhidup.snapsim.bank;

import id.my.kadaferhidup.snapsim.snap.SnapException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * The bank behind the SNAP endpoints: partners, accounts and intrabank transfers.
 *
 * <p>Rules that protect the money:
 * <ul>
 *   <li>A partner can only read or debit accounts it owns. Someone else's account answers exactly like an
 *       account that does not exist, so account numbers cannot be probed.</li>
 *   <li>Both accounts of a transfer are locked in account-number order before anything is read, so two
 *       transfers in opposite directions cannot deadlock and no balance is read stale.</li>
 *   <li>Balance check, debit and credit happen under those locks; a balance can never go below zero.</li>
 *   <li>Each transfer writes one debit and one credit of the same amount (double entry).</li>
 *   <li>partnerReferenceNo is unique per partner: a retry of the same request gets the original transfer,
 *       a different request with the same number is refused. Never two debits for one reference.</li>
 *   <li>Per-transaction and per-day limits on the source account.</li>
 * </ul>
 */
public final class Bank {

    public static final ZoneId ZONE = ZoneId.of("Asia/Jakarta");
    public static final String OWNER = "Ahmad Umraithi";

    /** Amounts are in sen: Rp1,00 = 100. */
    public static final long MAX_PER_TRANSACTION = 50_000_000_00L;
    public static final long MAX_PER_DAY = 100_000_000_00L;
    public static final long SANDBOX_MAIN_BALANCE = 25_000_000_00L;
    public static final long SANDBOX_SMALL_BALANCE = 2_500_000_00L;

    static final int MAX_PARTNERS = 5_000;
    static final Duration SANDBOX_LIFETIME = Duration.ofHours(24);
    static final int MAX_TRANSFERS_PER_PARTNER = 2_000;

    /** Fixed accounts every sandbox can send to. 8800778899 is dormant, to try the 403xx18 answer. */
    public static final String SHARED_ACTIVE_1 = "8800112233";
    public static final String SHARED_ACTIVE_2 = "8800445566";
    public static final String SHARED_DORMANT = "8800778899";

    public record Sandbox(Partner partner, List<Account> accounts) {
    }

    public record Entry(String referenceNo, String accountNo, String side, long amount, long balanceAfter, Instant at) {
    }

    public record TransferRequest(String partnerReferenceNo, String sourceAccountNo, String beneficiaryAccountNo,
                                  long amount, String remark, String transactionDate, String requestHash) {
    }

    private final Clock clock;
    private final SecureRandom random = new SecureRandom();
    private final Map<String, Partner> partners = new ConcurrentHashMap<>();
    private final Map<String, Account> accounts = new ConcurrentHashMap<>();
    /** key: partnerId + '\u0000' + partnerReferenceNo */
    private final Map<String, Transfer> byPartnerRef = new ConcurrentHashMap<>();
    private final Map<String, Transfer> byReferenceNo = new ConcurrentHashMap<>();
    private final Map<String, Integer> transferCount = new ConcurrentHashMap<>();
    private final AtomicLong totalDebits = new AtomicLong();
    private final AtomicLong totalCredits = new AtomicLong();
    private final AtomicLong sequence = new AtomicLong();
    private final List<Entry> recentEntries = new ArrayList<>();

    public Bank(Clock clock) {
        this.clock = clock;
        accounts.put(SHARED_ACTIVE_1, new Account(SHARED_ACTIVE_1, OWNER, null, Account.Status.ACTIVE, 0));
        accounts.put(SHARED_ACTIVE_2, new Account(SHARED_ACTIVE_2, OWNER, null, Account.Status.ACTIVE, 0));
        accounts.put(SHARED_DORMANT, new Account(SHARED_DORMANT, OWNER, null, Account.Status.DORMANT, 0));
    }

    // ------------------------------------------------------------------ partners

    /** A fresh partner with two funded accounts. The client secret is returned here and nowhere else. */
    public synchronized Sandbox createSandbox(PublicKey publicKey) {
        evictOldSandboxes();
        if (partners.size() >= MAX_PARTNERS) {
            throw SnapException.tooManyRequests();
        }
        String clientKey;
        do {
            clientKey = "SB" + hex(8);
        } while (partners.containsKey(clientKey));
        byte[] s = new byte[32];
        random.nextBytes(s);
        Partner p = new Partner(clientKey, Base64.getUrlEncoder().withoutPadding().encodeToString(s), publicKey, clock.instant());
        partners.put(clientKey, p);
        Account main = newAccount(OWNER, clientKey, SANDBOX_MAIN_BALANCE);
        Account small = newAccount(OWNER, clientKey, SANDBOX_SMALL_BALANCE);
        return new Sandbox(p, List.of(main, small));
    }

    /** Only for tests and the startup seed: a partner with a known secret. */
    public synchronized Sandbox addPartner(String clientKey, String clientSecret, PublicKey publicKey, long... balances) {
        Partner p = new Partner(clientKey, clientSecret, publicKey, clock.instant());
        partners.put(clientKey, p);
        List<Account> list = new ArrayList<>();
        for (long b : balances) {
            list.add(newAccount(OWNER, clientKey, b));
        }
        return new Sandbox(p, list);
    }

    public Optional<Partner> partner(String clientKey) {
        return clientKey == null ? Optional.empty() : Optional.ofNullable(partners.get(clientKey));
    }

    private Account newAccount(String name, String owner, long balance) {
        String no;
        do {
            no = String.valueOf(1_000_000_000L + (random.nextLong() & Long.MAX_VALUE) % 7_000_000_000L);
        } while (no.startsWith("88") || accounts.containsKey(no));
        Account a = new Account(no, name, owner, Account.Status.ACTIVE, balance);
        accounts.put(no, a);
        return a;
    }

    private void evictOldSandboxes() {
        Instant cutoff = clock.instant().minus(SANDBOX_LIFETIME);
        List<Partner> old = partners.values().stream().filter(p -> p.createdAt().isBefore(cutoff)).toList();
        if (partners.size() - old.size() >= MAX_PARTNERS) {
            old = partners.values().stream().sorted(Comparator.comparing(Partner::createdAt)).limit(partners.size() / 10 + 1).toList();
        }
        for (Partner p : old) {
            partners.remove(p.clientKey());
            accounts.values().removeIf(a -> a.ownedBy(p.clientKey()));
            byPartnerRef.values().removeIf(t -> t.partnerId().equals(p.clientKey()));
            byReferenceNo.values().removeIf(t -> t.partnerId().equals(p.clientKey()));
            transferCount.remove(p.clientKey());
        }
    }

    // ------------------------------------------------------------------ reads

    /** Balance inquiry: only the partner's own accounts. */
    public Account owned(String partnerId, String accountNo) {
        Account a = accountNo == null ? null : accounts.get(accountNo);
        if (a == null || !a.ownedBy(partnerId)) {
            throw SnapException.invalidAccount();
        }
        return a;
    }

    /** Account inquiry before a transfer: any account in this bank, name masked. */
    public Account beneficiary(String accountNo) {
        Account a = accountNo == null ? null : accounts.get(accountNo);
        if (a == null) {
            throw SnapException.invalidAccount();
        }
        return a;
    }

    /** Status inquiry: only transfers this partner made. */
    public Transfer transfer(String partnerId, String partnerReferenceNo, String referenceNo) {
        Transfer t = null;
        if (partnerReferenceNo != null) {
            t = byPartnerRef.get(partnerId + '\u0000' + partnerReferenceNo);
        }
        if (t == null && referenceNo != null) {
            Transfer r = byReferenceNo.get(referenceNo);
            t = r != null && r.partnerId().equals(partnerId) ? r : null;
        }
        if (t == null || (referenceNo != null && !t.referenceNo().equals(referenceNo))) {
            throw SnapException.transactionNotFound();
        }
        return t;
    }

    // ------------------------------------------------------------------ the money path

    public Transfer transfer(String partnerId, TransferRequest req) {
        Partner partner = partners.get(partnerId);
        if (partner == null) {
            throw SnapException.unauthorized("Unknown client");
        }
        // one partner's transfers are decided one at a time, so a reference can never be used twice
        synchronized (partner) {
            String key = partnerId + '\u0000' + req.partnerReferenceNo();
            Transfer existing = byPartnerRef.get(key);
            if (existing != null) {
                if (existing.requestHash().equals(req.requestHash())) {
                    return existing;
                }
                throw SnapException.duplicateReference();
            }
            if (transferCount.getOrDefault(partnerId, 0) >= MAX_TRANSFERS_PER_PARTNER) {
                throw SnapException.notPermitted("Sandbox transfer quota reached");
            }
            if (req.amount() <= 0) {
                throw SnapException.invalidFormat("amount.value");
            }
            if (req.amount() > MAX_PER_TRANSACTION) {
                throw SnapException.exceedsLimit();
            }
            Account src = owned(partnerId, req.sourceAccountNo());
            Account dst = beneficiary(req.beneficiaryAccountNo());
            if (src == dst) {
                throw SnapException.notPermitted("Source and beneficiary are the same account");
            }
            if (src.status() != Account.Status.ACTIVE || dst.status() != Account.Status.ACTIVE) {
                throw SnapException.inactiveAccount();
            }

            Account first = src.no().compareTo(dst.no()) < 0 ? src : dst;
            Account second = first == src ? dst : src;
            first.lock.lock();
            try {
                second.lock.lock();
                try {
                    Instant now = clock.instant();
                    LocalDate today = LocalDate.ofInstant(now, ZONE);
                    if (src.outgoingOn(today) + req.amount() > MAX_PER_DAY) {
                        throw SnapException.exceedsLimit();
                    }
                    if (src.balanceLocked() < req.amount()) {
                        throw SnapException.insufficientFunds();
                    }
                    String ref = referenceNo(now);
                    src.debit(req.amount(), today);
                    dst.credit(req.amount());
                    totalDebits.addAndGet(req.amount());
                    totalCredits.addAndGet(req.amount());
                    record(new Entry(ref, src.no(), "DEBIT", req.amount(), src.balanceLocked(), now));
                    record(new Entry(ref, dst.no(), "CREDIT", req.amount(), dst.balanceLocked(), now));
                    Transfer t = new Transfer(ref, req.partnerReferenceNo(), partnerId, src.no(), dst.no(), req.amount(),
                            req.remark(), req.transactionDate(), now, req.requestHash());
                    byPartnerRef.put(key, t);
                    byReferenceNo.put(ref, t);
                    transferCount.merge(partnerId, 1, Integer::sum);
                    return t;
                } finally {
                    second.lock.unlock();
                }
            } finally {
                first.lock.unlock();
            }
        }
    }

    private String referenceNo(Instant now) {
        long n = sequence.incrementAndGet() % 1_000_000;
        return String.format("%s%06d%04d", LocalDate.ofInstant(now, ZONE).toString().replace("-", "").substring(2), n,
                random.nextInt(10_000));
    }

    private void record(Entry e) {
        synchronized (recentEntries) {
            recentEntries.add(e);
            if (recentEntries.size() > 10_000) {
                recentEntries.subList(0, 1_000).clear();
            }
        }
    }

    // ------------------------------------------------------------------ checks

    /** Double entry: every rupiah debited was credited somewhere. */
    public boolean balanced() {
        return totalDebits.get() == totalCredits.get();
    }

    public long totalBalance() {
        return accounts.values().stream().mapToLong(Account::balance).sum();
    }

    int partnerCount() {
        return partners.size();
    }

    private String hex(int bytes) {
        byte[] b = new byte[bytes];
        random.nextBytes(b);
        StringBuilder sb = new StringBuilder();
        for (byte x : b) {
            sb.append(String.format("%02X", x));
        }
        return sb.toString();
    }
}
