package id.my.kadaferhidup.snapsim.snap;

import id.my.kadaferhidup.snapsim.bank.Account;
import id.my.kadaferhidup.snapsim.bank.Bank;
import id.my.kadaferhidup.snapsim.bank.Partner;
import id.my.kadaferhidup.snapsim.bank.Transfer;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/** The four SNAP services this bank offers, after {@link SnapGateway} has verified the request. */
public final class SnapServices {

    public static final String BALANCE = "11";
    public static final String ACCOUNT_INQUIRY_INTERNAL = "15";
    public static final String TRANSFER_INTRABANK = "17";
    public static final String TRANSFER_STATUS = "36";

    private static final Pattern REF = Pattern.compile("^[A-Za-z0-9-]{1,64}$");
    private static final Pattern ACCOUNT = Pattern.compile("^[0-9]{6,20}$");
    private static final Pattern VALUE = Pattern.compile("^(0|[1-9][0-9]{0,13})\\.[0-9]{2}$");

    private final Bank bank;
    private final Clock clock;

    public SnapServices(Bank bank, Clock clock) {
        this.bank = bank;
        this.clock = clock;
    }

    // ------------------------------------------------------------------ 11: /v1.0/balance-inquiry

    public Map<String, Object> balance(Partner p, Map<String, Object> body) {
        String ref = optionalRef(body, "partnerReferenceNo");
        String accountNo = account(body, "accountNo");
        Account a = bank.owned(p.clientKey(), accountNo);
        long bal = a.balance();
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("balanceType", "Cash");
        info.put("amount", money(bal));
        info.put("floatAmount", money(0));
        info.put("holdAmount", money(0));
        info.put("availableBalance", money(bal));
        info.put("ledgerBalance", money(bal));
        info.put("status", a.status() == Account.Status.ACTIVE ? "0001" : "0002");
        Map<String, Object> out = ok(BALANCE);
        out.put("partnerReferenceNo", ref);
        out.put("accountNo", a.no());
        out.put("name", a.name());
        out.put("accountInfos", List.of(info));
        return out;
    }

    // ------------------------------------------------------------------ 15: /v1.0/account-inquiry-internal

    public Map<String, Object> accountInquiry(Partner p, Map<String, Object> body) {
        String ref = optionalRef(body, "partnerReferenceNo");
        Account a = bank.beneficiary(account(body, "beneficiaryAccountNo"));
        Map<String, Object> out = ok(ACCOUNT_INQUIRY_INTERNAL);
        out.put("partnerReferenceNo", ref);
        out.put("beneficiaryAccountNo", a.no());
        out.put("beneficiaryAccountName", Account.mask(a.name()));
        out.put("beneficiaryAccountStatus", a.status() == Account.Status.ACTIVE ? "Rekening aktif" : "Rekening dormant");
        out.put("beneficiaryAccountType", "D");
        out.put("currency", "IDR");
        return out;
    }

    // ------------------------------------------------------------------ 17: /v1.0/transfer-intrabank

    public Map<String, Object> transfer(Partner p, Map<String, Object> body) {
        String ref = requiredRef(body, "partnerReferenceNo");
        long amount = amount(body);
        String source = account(body, "sourceAccountNo");
        String beneficiary = account(body, "beneficiaryAccountNo");
        String remark = text(body, "remark", 50);
        String trxDate = transactionDate(body);
        // what makes two requests "the same transfer": the money fields, not the timestamp of a retry
        String requestHash = source + "|" + beneficiary + "|" + amount + "|" + (remark == null ? "" : remark);
        Transfer t = bank.transfer(p.clientKey(),
                new Bank.TransferRequest(ref, source, beneficiary, amount, remark, trxDate, requestHash));
        Map<String, Object> out = ok(TRANSFER_INTRABANK);
        out.put("referenceNo", t.referenceNo());
        out.put("partnerReferenceNo", t.partnerReferenceNo());
        out.put("amount", money(t.amount()));
        out.put("beneficiaryAccountNo", t.beneficiaryAccountNo());
        out.put("sourceAccountNo", t.sourceAccountNo());
        out.put("transactionDate", t.transactionDate());
        return out;
    }

    // ------------------------------------------------------------------ 36: /v1.0/transfer/status

    public Map<String, Object> status(Partner p, Map<String, Object> body) {
        String origRef = requiredRef(body, "originalPartnerReferenceNo");
        Object rn = body.get("originalReferenceNo");
        String origReferenceNo = rn == null || rn.toString().isBlank() ? null : rn.toString();
        if (origReferenceNo != null && !REF.matcher(origReferenceNo).matches()) {
            throw SnapException.invalidFormat("originalReferenceNo");
        }
        Object sc = body.get("serviceCode");
        if (sc == null) {
            throw SnapException.missing("serviceCode");
        }
        if (!TRANSFER_INTRABANK.equals(sc.toString())) {
            throw SnapException.invalidFormat("serviceCode");
        }
        Transfer t = bank.transfer(p.clientKey(), origRef, origReferenceNo);
        Map<String, Object> out = ok(TRANSFER_STATUS);
        out.put("originalReferenceNo", t.referenceNo());
        out.put("originalPartnerReferenceNo", t.partnerReferenceNo());
        out.put("serviceCode", TRANSFER_INTRABANK);
        out.put("transactionDate", t.transactionDate());
        out.put("amount", money(t.amount()));
        out.put("beneficiaryAccountNo", t.beneficiaryAccountNo());
        out.put("sourceAccountNo", t.sourceAccountNo());
        out.put("latestTransactionStatus", "00");
        out.put("transactionStatusDesc", "Success");
        return out;
    }

    // ------------------------------------------------------------------ field rules

    private static Map<String, Object> ok(String service) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("responseCode", "200" + service + "00");
        out.put("responseMessage", "Successful");
        return out;
    }

    public static Map<String, Object> money(long sen) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("value", String.format("%d.%02d", sen / 100, sen % 100));
        m.put("currency", "IDR");
        return m;
    }

    /** "150000.00" IDR → 15000000 sen. Exactly two decimals, as strings, so no rounding ever happens. */
    static long amount(Map<String, Object> body) {
        if (!(body.get("amount") instanceof Map<?, ?> m)) {
            throw body.get("amount") == null ? SnapException.missing("amount") : SnapException.invalidFormat("amount");
        }
        Object value = m.get("value");
        Object currency = m.get("currency");
        if (value == null) {
            throw SnapException.missing("amount.value");
        }
        if (currency == null) {
            throw SnapException.missing("amount.currency");
        }
        if (!(value instanceof String v) || !VALUE.matcher(v).matches()) {
            throw SnapException.invalidFormat("amount.value");
        }
        if (!"IDR".equals(currency)) {
            throw SnapException.invalidFormat("amount.currency");
        }
        int dot = v.indexOf('.');
        return Math.addExact(Math.multiplyExact(Long.parseLong(v.substring(0, dot)), 100L), Long.parseLong(v.substring(dot + 1)));
    }

    private static String requiredRef(Map<String, Object> body, String field) {
        Object v = body.get(field);
        if (v == null || v.toString().isBlank()) {
            throw SnapException.missing(field);
        }
        if (!(v instanceof String s) || !REF.matcher(s).matches()) {
            throw SnapException.invalidFormat(field);
        }
        return s;
    }

    private static String optionalRef(Map<String, Object> body, String field) {
        return body.get(field) == null ? null : requiredRef(body, field);
    }

    private static String account(Map<String, Object> body, String field) {
        Object v = body.get(field);
        if (v == null || v.toString().isBlank()) {
            throw SnapException.missing(field);
        }
        if (!(v instanceof String s) || !ACCOUNT.matcher(s).matches()) {
            throw SnapException.invalidFormat(field);
        }
        return s;
    }

    private static String text(Map<String, Object> body, String field, int max) {
        Object v = body.get(field);
        if (v == null) {
            return null;
        }
        if (!(v instanceof String s) || s.length() > max || s.chars().anyMatch(Character::isISOControl)) {
            throw SnapException.invalidFormat(field);
        }
        return s.isBlank() ? null : s.strip();
    }

    private String transactionDate(Map<String, Object> body) {
        Object v = body.get("transactionDate");
        if (v == null || v.toString().isBlank()) {
            return OffsetDateTime.now(clock.withZone(Bank.ZONE)).truncatedTo(ChronoUnit.SECONDS).toString();
        }
        if (!(v instanceof String s) || s.length() > 40) {
            throw SnapException.invalidFormat("transactionDate");
        }
        try {
            OffsetDateTime.parse(s);
            return s;
        } catch (DateTimeParseException e) {
            throw SnapException.invalidFormat("transactionDate");
        }
    }
}
