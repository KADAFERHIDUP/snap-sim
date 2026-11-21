package id.my.kadaferhidup.snapsim.snap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

class SignaturesTest {

    static KeyPair rsa(int bits) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(bits);
        return g.generateKeyPair();
    }

    @Test
    void hmacMatchesRfc4231TestCase2() {
        String expectedHex = "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737";
        String b64 = Signatures.hmacSha512("Jefe", "what do ya want for nothing?");
        assertEquals(expectedHex, HexFormat.of().formatHex(Base64.getDecoder().decode(b64)));
    }

    @Test
    void minifyRemovesWhitespaceOnlyOutsideStrings() {
        String pretty = "{\n  \"remark\" : \"Bayar  sewa \\\" ruko\",\n  \"amount\": { \"value\": \"10000.00\" }\n}";
        assertEquals("{\"remark\":\"Bayar  sewa \\\" ruko\",\"amount\":{\"value\":\"10000.00\"}}", Signatures.minify(pretty));
    }

    @Test
    void prettyAndCompactBodiesHashTheSame() {
        assertEquals(Signatures.bodyHash("{\"a\":\"1\"}"), Signatures.bodyHash("{ \"a\" : \"1\" }\n"));
        // SHA-256 of the empty string, lowercase hex
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", Signatures.bodyHash(""));
    }

    @Test
    void stringToSignHasTheSnapLayout() {
        String s = Signatures.transactionStringToSign("post", "/snap/v1.0/balance-inquiry", "TOKEN", "{}", "2026-11-21T10:00:00+07:00");
        assertEquals("POST:/snap/v1.0/balance-inquiry:TOKEN:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a:2026-11-21T10:00:00+07:00", s);
    }

    @Test
    void rsaSignatureVerifiesOnlyWithTheRightKey() throws Exception {
        KeyPair a = rsa(2048);
        KeyPair b = rsa(2048);
        String sts = Signatures.tokenStringToSign("SB01", "2026-11-21T10:00:00+07:00");
        String sig = Signatures.signRsa(a.getPrivate(), sts);
        assertTrue(Signatures.verifyRsa(a.getPublic(), sts, sig));
        assertFalse(Signatures.verifyRsa(b.getPublic(), sts, sig), "kunci lain");
        assertFalse(Signatures.verifyRsa(a.getPublic(), sts + "x", sig), "isi diubah");
        assertFalse(Signatures.verifyRsa(a.getPublic(), sts, "bukan-base64!"), "tanda tangan rusak");
    }

    @Test
    void publicKeyParsingAcceptsSpkiAndRefusesWeakKeys() throws Exception {
        KeyPair ok = rsa(2048);
        String spki = Base64.getEncoder().encodeToString(ok.getPublic().getEncoded());
        assertEquals(ok.getPublic(), Signatures.parsePublicKey(spki));
        assertEquals(ok.getPublic(), Signatures.parsePublicKey("-----BEGIN PUBLIC KEY-----\n" + spki + "\n-----END PUBLIC KEY-----"));
        String weak = Base64.getEncoder().encodeToString(rsa(1024).getPublic().getEncoded());
        assertThrows(SnapException.class, () -> Signatures.parsePublicKey(weak));
        assertThrows(SnapException.class, () -> Signatures.parsePublicKey("sampah"));
        assertThrows(SnapException.class, () -> Signatures.parsePublicKey(null));
    }

    @Test
    void hmacComparisonRejectsTamperedOrMalformedSignatures() {
        String sts = "POST:/x:T:h:ts";
        String sig = Signatures.hmacSha512("rahasia", sts);
        assertTrue(Signatures.verifyHmac("rahasia", sts, sig));
        assertFalse(Signatures.verifyHmac("rahasia2", sts, sig));
        assertFalse(Signatures.verifyHmac("rahasia", sts, sig.substring(1)));
        assertFalse(Signatures.verifyHmac("rahasia", sts, "%%%"));
    }

    @Test
    void responseCodeIsHttpPlusServicePlusCase() {
        assertEquals("4091100", SnapException.conflict().code("11"));
        assertEquals("4031714", SnapException.insufficientFunds().code("17"));
        assertEquals("4017301", SnapException.invalidToken().code("73"));
    }
}
