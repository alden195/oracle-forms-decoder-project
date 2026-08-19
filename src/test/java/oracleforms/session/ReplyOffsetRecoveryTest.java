package oracleforms.session;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Optional;
import java.util.Random;
import oracleforms.codec.Rc4Stream;
import oracleforms.codec.TestPackets;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Recovering the offset a reply was really encrypted at.
 *
 * <p>The situation being reproduced is the one the live target produced on 2026-08-18: an appended
 * message was <em>accepted</em>, and its reply came back unreadable because the server had flushed a
 * response down the client's outstanding long-poll first. The response tail measured from proxy
 * history is short by exactly that response's length, and that length is not knowable when the
 * message is sent.
 *
 * <p>What matters as much as finding the offset is refusing to invent one, so the tests below spend
 * more effort on the cases where nothing should be found than on the happy path.
 */
class ReplyOffsetRecoveryTest {

    private static final byte[] KEY = {0x4C, (byte) 0xB1, (byte) 0xAE, 0x07, (byte) 0xD9};

    /**
     * A reply built from ids that are actually in the table.
     *
     * <p>That is the whole point of the exercise — the verifier asks whether the decrypted ids are
     * real, so a packet of invented ones would be indistinguishable from noise and could never be
     * recovered. {@code NAME}, {@code PARENT}, {@code CANCEL} and {@code COLWIDTH}.
     */
    private static byte[] replyPacket() {
        return new TestPackets()
                .message(0x1000, 0, 40)
                .int32Property(109, 4711)
                .stringProperty(103, 12, "recovered")
                .boolProperty(105, true)
                .int32Property(104, 12)
                .endProperties()
                .endPacket()
                .build();
    }

    private static byte[] encryptedAt(byte[] plaintext, long offset) {
        Rc4Stream cipher = new Rc4Stream(KEY);
        cipher.skip((int) offset);
        return cipher.applied(plaintext);
    }

    @Test
    @DisplayName("finds the offset when a response the ledger never saw has gone by")
    void findsTheOffsetPastAnUnseenResponse() {
        byte[] reply = replyPacket();

        // The ledger thinks the server's response cipher is at 4000. It is really 6251 bytes
        // further on, because the outstanding poll was answered first -- 6251 is a real response
        // length from the capture.
        long ledgerThinks = 4000;
        long truth = ledgerThinks + 6251;

        Optional<ReplyOffsetRecovery.Found> found =
                ReplyOffsetRecovery.search(KEY, encryptedAt(reply, truth), ledgerThinks);

        assertTrue(found.isPresent(), "the offset should have been recoverable");
        assertEquals(truth, found.get().offset());
        assertEquals(6251, found.get().gap(), "the gap is the missing response's length");
        assertEquals(1.0, found.get().signals().knownFraction());
    }

    @Test
    @DisplayName("finds it when the ledger is already right, reporting a gap of zero")
    void findsAZeroGap() {
        byte[] reply = replyPacket();
        Optional<ReplyOffsetRecovery.Found> found =
                ReplyOffsetRecovery.search(KEY, encryptedAt(reply, 1234), 1234);

        assertTrue(found.isPresent());
        assertEquals(0, found.get().gap());
    }

    @Test
    @DisplayName("the recovered offset actually decrypts the reply")
    void theRecoveredOffsetDecrypts() {
        byte[] reply = replyPacket();
        long truth = 900 + 2048;
        byte[] ciphertext = encryptedAt(reply, truth);

        ReplyOffsetRecovery.Found found =
                ReplyOffsetRecovery.search(KEY, ciphertext, 900).orElseThrow();

        Rc4Stream cipher = new Rc4Stream(KEY);
        cipher.skip((int) found.offset());
        assertArrayEquals(reply, cipher.applied(ciphertext));
    }

    @Test
    @DisplayName("refuses when the true offset is behind the ledger, rather than inventing one")
    void refusesWhenTheTruthIsBehind() {
        byte[] ciphertext = encryptedAt(replyPacket(), 500);

        // Searching forward from a position past the truth must find nothing. The ledger can be
        // short of the server but never ahead of it, so a hit here would be a false positive.
        assertTrue(ReplyOffsetRecovery.search(KEY, ciphertext, 5000, 4096).isEmpty());
    }

    @Test
    @DisplayName("refuses on a body that is not FHT at any offset")
    void refusesOnNoise() {
        byte[] noise = new byte[120];
        new Random(20260818L).nextBytes(noise);

        assertTrue(ReplyOffsetRecovery.search(KEY, noise, 0, 8192).isEmpty(),
                "random bytes must not be talked into looking like a message");
    }

    @Test
    @DisplayName("refuses on a wrong key, which is the same shape of mistake")
    void refusesOnTheWrongKey() {
        byte[] ciphertext = encryptedAt(replyPacket(), 3000);
        byte[] wrongKey = {0x4C, (byte) 0xB1, (byte) 0xAE, 0x07, (byte) 0xDA};

        assertTrue(ReplyOffsetRecovery.search(wrongKey, ciphertext, 2000, 8192).isEmpty());
    }

    @Test
    @DisplayName("refuses when the answer lies outside the window rather than picking the best miss")
    void refusesOutsideTheWindow() {
        byte[] ciphertext = encryptedAt(replyPacket(), 50_000);
        assertTrue(ReplyOffsetRecovery.search(KEY, ciphertext, 0, 1024).isEmpty());
    }

    /**
     * The live case from 2026-08-18, reproduced exactly.
     *
     * <p>The target's reply was found at an offset whose plaintext had <strong>4 of 4</strong>
     * property ids known and consumed 31 bytes without reaching a terminator — so
     * {@link ReplyOffsetRecovery#search} refused it, correctly, because that is the gate for moving a
     * live session's ledger. The pane meanwhile went on showing the ledger's own reading, which had
     * 2 of 9 ids known.
     *
     * <p>Both halves of that are pinned here: the strict gate must keep refusing (it guards bytes
     * that later reach the wire), and the candidate must still be <em>reported</em>, because
     * {@code RepeaterSendInterceptor.readsAsFht} — the same class's test for "this decoded correctly"
     * — passes at 4/4 and would have shown it. A system that calls a reading too weak to display and
     * simultaneously good enough to call the other one wrong is contradicting itself.
     */
    @Test
    @DisplayName("a 4/4-but-truncated candidate is refused for the ledger yet still reported")
    void truncatedButFullyKnownIsReportedNotAccepted() {
        // Dropping the last two bytes removes the terminator: 31 bytes consumed, 4/4 ids known.
        byte[] full = replyPacket();
        byte[] truncated = java.util.Arrays.copyOf(full, full.length - 2);

        KeyValidation.Signals shape = KeyValidation.signalsOf(truncated);
        assertEquals(1.0, shape.knownFraction(), "fixture must match the live case: every id known");
        assertTrue(!shape.complete(), "fixture must match the live case: no terminator reached");

        byte[] ciphertext = encryptedAt(truncated, 9000);
        ReplyOffsetRecovery.Scan scan = ReplyOffsetRecovery.scan(KEY, ciphertext, 6000, 8192);

        assertTrue(scan.accepted().isEmpty(),
                "an incomplete parse must not move a live session's response ledger");
        assertTrue(scan.closest().isPresent(), "but the candidate must not be thrown away silently");
        assertEquals(9000, scan.closest().orElseThrow().offset(),
                "and the candidate reported must be the true offset");
        assertTrue(scan.closest().orElseThrow().signals().knownFraction()
                        >= KeyValidation.MIN_KNOWN_FRACTION,
                "it clears the bar the interceptor uses to call a reply correctly decoded, so "
                        + "withholding it from the display would contradict that test");
    }

    /**
     * A refusal has to be diagnosable, because the two reasons it happens need opposite fixes.
     *
     * <p>"No offset in this window decrypts the body" means the window is too small or the ledger is
     * wrong about something bigger. "The right-looking offset was rejected for one unknown property
     * id" means the acceptance gate is too strict for real traffic. A bare empty {@code Optional}
     * cannot tell those apart, and the first live failures were diagnosed by reading source rather
     * than logs precisely because it could not.
     */
    @Test
    @DisplayName("a refusal reports the closest candidate it saw, so the reason is diagnosable")
    void refusalCarriesItsNearestMiss() {
        byte[] ciphertext = encryptedAt(replyPacket(), 3000);

        // Searching from past the truth finds nothing believable, by design.
        ReplyOffsetRecovery.Scan scan = ReplyOffsetRecovery.scan(KEY, ciphertext, 6000, 4096);
        assertTrue(scan.accepted().isEmpty(), "nothing here should be believed");
        assertTrue(scan.describeRefusal().length() > 0, "a refusal must say something");

        // And when the answer is in range, the closest candidate is that answer.
        ReplyOffsetRecovery.Scan hit = ReplyOffsetRecovery.scan(KEY, ciphertext, 2000, 4096);
        assertTrue(hit.accepted().isPresent());
        assertEquals(hit.accepted().orElseThrow().offset(), hit.closest().orElseThrow().offset(),
                "the accepted offset is by definition also the closest one");
    }

    @Test
    @DisplayName("a full-size window over noise yields nothing, run enough times to mean it")
    void theFullWindowDoesNotManufactureAnAnswer() {
        // The bar has to hold against the number of chances a real search gives it, which is a
        // quarter of a million offsets — not against one. At three properties it did not: a body of
        // noise found a "clean" offset 133,417 bytes away during development, which is why the
        // threshold also demands a parse that reaches the terminator.
        Random random = new Random(20260818L);
        for (int trial = 0; trial < 8; trial++) {
            byte[] noise = new byte[128];
            random.nextBytes(noise);
            Optional<ReplyOffsetRecovery.Found> found =
                    ReplyOffsetRecovery.search(KEY, noise, 0, ReplyOffsetRecovery.DEFAULT_WINDOW);
            assertTrue(found.isEmpty(),
                    "trial " + trial + " invented " + found.map(ReplyOffsetRecovery.Found::describe)
                            .orElse(""));
        }
    }

    @Test
    @DisplayName("a short acknowledgement carries no evidence, so nothing is claimed about it")
    void shortRepliesAreNotJudged() {
        byte[] tiny = encryptedAt(new byte[]{0x11, (byte) 0xAE}, 700);
        assertTrue(ReplyOffsetRecovery.search(KEY, tiny, 700, 4096).isEmpty(),
                "two bytes cannot establish an offset, and pretending otherwise would resynchronise "
                        + "the ledger on a coincidence");
    }
}
