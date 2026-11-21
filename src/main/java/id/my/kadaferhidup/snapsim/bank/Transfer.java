package id.my.kadaferhidup.snapsim.bank;

import java.time.Instant;

/**
 * A completed intrabank transfer. {@code requestHash} lets a retry with the same partnerReferenceNo
 * get the original answer, while a different request reusing the number is refused.
 */
public record Transfer(String referenceNo, String partnerReferenceNo, String partnerId, String sourceAccountNo,
                       String beneficiaryAccountNo, long amount, String remark, String transactionDate,
                       Instant createdAt, String requestHash) {
}
