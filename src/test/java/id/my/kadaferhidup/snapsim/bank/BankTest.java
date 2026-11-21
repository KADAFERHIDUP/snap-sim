package id.my.kadaferhidup.snapsim.bank;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import id.my.kadaferhidup.snapsim.snap.SnapException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class BankTest {

    static final long RP = 100; // one rupiah in sen

    Bank bank;
    String a;
    String a2;
    String b;

    @BeforeEach
    void setUp() {
        bank = new Bank(Clock.fixed(Instant.parse("2026-11-21T03:00:00Z"), ZoneOffset.UTC));
        Bank.Sandbox pa = bank.addPartner("PA", "secret-a", null, 1_000_000 * RP, 0);
        Bank.Sandbox pb = bank.addPartner("PB", "secret-b", null, 500_000 * RP);
        a = pa.accounts().get(0).no();
        a2 = pa.accounts().get(1).no();
        b = pb.accounts().get(0).no();
    }

    Bank.TransferRequest req(String ref, String from, String to, long amount) {
        return new Bank.TransferRequest(ref, from, to, amount, null, "2026-11-21T10:00:00+07:00", from + "|" + to + "|" + amount);
    }

    static String code(Runnable r, String service) {
        return assertThrows(SnapException.class, r::run).code(service);
    }

    @Test
    void transferMovesMoneyWithOneDebitAndOneCredit() {
        Transfer t = bank.transfer("PA", req("R1", a, b, 150_000 * RP));
        assertEquals(850_000 * RP, bank.owned("PA", a).balance());
        assertEquals(650_000 * RP, bank.owned("PB", b).balance());
        assertTrue(bank.balanced());
        assertEquals(t, bank.transfer("PA", "R1", null));
    }

    @Test
    void balanceCanNeverGoNegative() {
        assertEquals("4031714", code(() -> bank.transfer("PA", req("R1", a2, b, RP)), "17"));
        assertEquals(0, bank.owned("PA", a2).balance());
    }

    @Test
    void perTransactionAndDailyLimitsHold() {
        assertEquals("4031702", code(() -> bank.transfer("PA", req("R1", a, b, Bank.MAX_PER_TRANSACTION + 1)), "17"));
        Bank.Sandbox rich = bank.addPartner("RICH", "s", null, 300_000_000 * RP);
        String r = rich.accounts().get(0).no();
        bank.transfer("RICH", req("D1", r, b, 50_000_000 * RP));
        bank.transfer("RICH", req("D2", r, b, 50_000_000 * RP));
        assertEquals("4031702", code(() -> bank.transfer("RICH", req("D3", r, b, RP)), "17"));
    }

    @Test
    void retryWithTheSameReferenceIsAnsweredWithoutASecondDebit() {
        Transfer first = bank.transfer("PA", req("R1", a, b, 10_000 * RP));
        Transfer again = bank.transfer("PA", req("R1", a, b, 10_000 * RP));
        assertSame(first, again);
        assertEquals(990_000 * RP, bank.owned("PA", a).balance());
        assertEquals("4091701", code(() -> bank.transfer("PA", req("R1", a, b, 99_000 * RP)), "17"));
    }

    @Test
    void referencesBelongToOnePartner() {
        bank.transfer("PA", req("SAME", a, b, RP));
        Transfer pbOwn = bank.transfer("PB", req("SAME", b, a, RP));
        assertEquals("PB", pbOwn.partnerId());
        assertEquals("4043601", code(() -> bank.transfer("PB", "R-unknown", null), "36"));
        Transfer pa = bank.transfer("PA", "SAME", null);
        assertEquals("4043601", code(() -> bank.transfer("PB", null, pa.referenceNo()), "36"), "status transfer orang lain");
    }

    @Test
    void someoneElsesAccountLooksLikeNoAccount() {
        assertEquals("4041111", code(() -> bank.owned("PB", a), "11"));
        assertEquals("4041111", code(() -> bank.owned("PB", "1234567890"), "11"));
        assertEquals("4041711", code(() -> bank.transfer("PB", req("X", a, b, RP)), "17"), "mendebit rekening orang lain");
        assertEquals(1_000_000 * RP, bank.owned("PA", a).balance());
    }

    @Test
    void dormantAndSameAccountTransfersAreRefused() {
        assertEquals("4031718", code(() -> bank.transfer("PA", req("R1", a, Bank.SHARED_DORMANT, RP)), "17"));
        assertEquals("4031715", code(() -> bank.transfer("PA", req("R2", a, a, RP)), "17"));
    }

    @Test
    void thirtyParallelTransfersFromOneAccountNeverOverdraw() throws Exception {
        // 1.000.000 / 40.000 = 25 can succeed, the other 5 must be refused
        ExecutorService pool = Executors.newFixedThreadPool(30);
        CountDownLatch go = new CountDownLatch(1);
        AtomicInteger ok = new AtomicInteger();
        AtomicInteger insufficient = new AtomicInteger();
        List<Future<?>> fs = new ArrayList<>();
        for (int i = 0; i < 30; i++) {
            int n = i;
            fs.add(pool.submit(() -> {
                go.await();
                try {
                    bank.transfer("PA", req("P" + n, a, i(n), 40_000 * RP));
                    ok.incrementAndGet();
                } catch (SnapException e) {
                    insufficient.incrementAndGet();
                }
                return null;
            }));
        }
        go.countDown();
        for (Future<?> f : fs) {
            f.get();
        }
        pool.shutdown();
        assertEquals(25, ok.get());
        assertEquals(5, insufficient.get());
        assertEquals(0, bank.owned("PA", a).balance());
        assertTrue(bank.balanced());
    }

    private String i(int n) {
        return n % 2 == 0 ? Bank.SHARED_ACTIVE_1 : b;
    }

    @Test
    void transfersInOppositeDirectionsDoNotDeadlock() throws Exception {
        long before = bank.totalBalance();
        ExecutorService pool = Executors.newFixedThreadPool(16);
        List<Future<?>> fs = new ArrayList<>();
        for (int i = 0; i < 400; i++) {
            int n = i;
            fs.add(pool.submit(() -> n % 2 == 0 ? bank.transfer("PA", req("A" + n, a, b, RP))
                    : bank.transfer("PB", req("B" + n, b, a, RP))));
        }
        for (Future<?> f : fs) {
            f.get(10, java.util.concurrent.TimeUnit.SECONDS);
        }
        pool.shutdown();
        assertEquals(before, bank.totalBalance(), "tidak ada uang yang muncul atau hilang");
        assertEquals(1_000_000 * RP, bank.owned("PA", a).balance());
    }

    @Test
    void namesAreMaskedForInquiry() {
        assertEquals("Ah*** Um******", Account.mask("Ahmad Umraithi"));
        assertEquals("Al", Account.mask("Al"));
    }
}
