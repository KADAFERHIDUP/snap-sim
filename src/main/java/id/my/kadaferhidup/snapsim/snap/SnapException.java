package id.my.kadaferhidup.snapsim.snap;

/**
 * A SNAP error. The 7-digit response code is HTTP status + service code + case code,
 * so the same failure reads {@code 4011100} on balance inquiry and {@code 4011700} on transfer.
 */
public final class SnapException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final int http;
    private final String caseCode;

    public SnapException(int http, String caseCode, String message) {
        super(message, null, false, false);
        this.http = http;
        this.caseCode = caseCode;
    }

    public int http() {
        return http;
    }

    public String code(String serviceCode) {
        return http + serviceCode + caseCode;
    }

    // ------------------------------------------------------------------ the cases this simulator uses

    public static SnapException badRequest() {
        return new SnapException(400, "00", "Bad Request");
    }

    public static SnapException invalidFormat(String field) {
        return new SnapException(400, "01", "Invalid Field Format " + field);
    }

    public static SnapException missing(String field) {
        return new SnapException(400, "02", "Invalid Mandatory Field " + field);
    }

    public static SnapException unauthorized(String reason) {
        return new SnapException(401, "00", "Unauthorized. " + reason);
    }

    public static SnapException invalidToken() {
        return new SnapException(401, "01", "Invalid Token (B2B)");
    }

    public static SnapException exceedsLimit() {
        return new SnapException(403, "02", "Exceeds Transaction Amount Limit");
    }

    public static SnapException insufficientFunds() {
        return new SnapException(403, "14", "Insufficient Funds");
    }

    public static SnapException notPermitted(String reason) {
        return new SnapException(403, "15", "Transaction Not Permitted. " + reason);
    }

    public static SnapException inactiveAccount() {
        return new SnapException(403, "18", "Inactive Card/Account/Customer");
    }

    public static SnapException transactionNotFound() {
        return new SnapException(404, "01", "Transaction Not Found");
    }

    public static SnapException invalidAccount() {
        return new SnapException(404, "11", "Invalid Card/Account/Customer");
    }

    public static SnapException conflict() {
        return new SnapException(409, "00", "Conflict");
    }

    public static SnapException duplicateReference() {
        return new SnapException(409, "01", "Duplicate partnerReferenceNo");
    }

    public static SnapException tooManyRequests() {
        return new SnapException(429, "00", "Too Many Requests");
    }

    public static SnapException general() {
        return new SnapException(500, "00", "General Error");
    }
}
