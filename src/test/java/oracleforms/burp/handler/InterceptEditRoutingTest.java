package oracleforms.burp.handler;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import oracleforms.burp.repeater.DraftMarkers;
import oracleforms.burp.repeater.SendMode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Where an in-flight edit is routed, and the one thing that must never happen to it.
 *
 * <p>The invariant: <strong>a request carrying intercept markers is never {@code NOT_MINE}.</strong>
 * Its body is FHT plaintext by construction, so any answer that let it continue down another path
 * would put decoded traffic — credentials included — on the wire. Two such paths exist and both
 * looked reasonable:
 *
 * <ul>
 *   <li>{@code RepeaterSendInterceptor}, which sees the markers, correctly judges that a marker on
 *       <em>proxied</em> traffic was set by the client, and strips them and forwards the body. That
 *       rule is right for every other mode and catastrophic for this one, which is why Mode D is
 *       dispatched ahead of it.
 *   <li>The ordinary forwarding path, which would treat the plaintext as ciphertext.
 * </ul>
 *
 * <p>The decision is tested rather than the handler because {@code RequestToBeSentAction}'s
 * factories need a running Burp — the same reason {@code RefusalResponseTest} tests the refusal's
 * bytes rather than its response object.
 */
class InterceptEditRoutingTest {

    private static final String TOKEN = "cafebabecafebabecafebabecafebabe";

    private static Optional<DraftMarkers> intercept(String token) {
        return Optional.of(new DraftMarkers("session-1", SendMode.INTERCEPT, 9, 42, token, 0L));
    }

    /** A token checker that accepts exactly one value, once, and counts how often it was asked. */
    private static final class OneShot implements java.util.function.Predicate<String> {
        private final AtomicInteger calls = new AtomicInteger();
        private String valid;

        OneShot(String valid) {
            this.valid = valid;
        }

        @Override
        public boolean test(String token) {
            calls.incrementAndGet();
            if (valid != null && valid.equals(token)) {
                valid = null;
                return true;
            }
            return false;
        }
    }

    @Test
    @DisplayName("an authorised in-flight edit is encrypted")
    void authorisedEditIsEncrypted() {
        FormsHttpHandler.EditRoute route =
                FormsHttpHandler.routeFor(intercept(TOKEN), true, new OneShot(TOKEN));

        assertEquals(FormsHttpHandler.EditRoute.Decision.ENCRYPT, route.decision());
    }

    @Test
    @DisplayName("a request with no markers is left to the ordinary paths")
    void unmarkedRequestsAreNotClaimed() {
        assertEquals(FormsHttpHandler.EditRoute.Decision.NOT_MINE,
                FormsHttpHandler.routeFor(Optional.empty(), true, new OneShot(TOKEN)).decision());
    }

    @Test
    @DisplayName("the other send modes are left to the Repeater interceptor, which owns them")
    void otherModesAreNotClaimed() {
        for (SendMode mode : new SendMode[]{SendMode.TAIL, SendMode.OFFSET}) {
            Optional<DraftMarkers> markers =
                    Optional.of(new DraftMarkers("session-1", mode, 9));
            assertEquals(FormsHttpHandler.EditRoute.Decision.NOT_MINE,
                    FormsHttpHandler.routeFor(markers, true, new OneShot(TOKEN)).decision(),
                    mode + " is not an in-flight edit and must not be claimed here");
        }
    }

    @Test
    @DisplayName("an unauthorised edit is dropped, never forwarded: the body is plaintext")
    void unauthorisedEditIsDropped() {
        FormsHttpHandler.EditRoute route =
                FormsHttpHandler.routeFor(intercept("not-the-right-token"), true, new OneShot(TOKEN));

        assertEquals(FormsHttpHandler.EditRoute.Decision.DROP, route.decision());
        assertFalse(route.reason().isBlank(), "a drop must say why; the log is the only channel");
    }

    @Test
    @DisplayName("a missing token is dropped rather than treated as an absent marker")
    void aMissingTokenIsDropped() {
        assertEquals(FormsHttpHandler.EditRoute.Decision.DROP,
                FormsHttpHandler.routeFor(intercept(null), true, new OneShot(TOKEN)).decision());
    }

    @Test
    @DisplayName("a token works once; a replay of the same request is dropped")
    void aReplayedEditIsDropped() {
        OneShot tokens = new OneShot(TOKEN);

        assertEquals(FormsHttpHandler.EditRoute.Decision.ENCRYPT,
                FormsHttpHandler.routeFor(intercept(TOKEN), true, tokens).decision());

        // Burp calling the handler twice for one request, or the user resending the tab. Either way
        // the ledger has already moved past this message, so encrypting again would be wrong — and
        // forwarding the plaintext would be worse.
        assertEquals(FormsHttpHandler.EditRoute.Decision.DROP,
                FormsHttpHandler.routeFor(intercept(TOKEN), true, tokens).decision());
    }

    @Test
    @DisplayName("with the edit path unavailable the request is still claimed, and dropped")
    void anUnavailablePathStillClaimsTheRequest() {
        OneShot tokens = new OneShot(TOKEN);
        FormsHttpHandler.EditRoute route =
                FormsHttpHandler.routeFor(intercept(TOKEN), false, tokens);

        assertEquals(FormsHttpHandler.EditRoute.Decision.DROP, route.decision());
        assertEquals(0, tokens.calls.get(),
                "there is nothing to authorise against, so the capability is not spent either");
    }

    @Test
    @DisplayName("every intercept-marked request is claimed, whatever else is true of it")
    void interceptMarkedRequestsAreAlwaysClaimed() {
        // The property in one place. Any NOT_MINE here is decoded FHT reaching the wire.
        for (String token : new String[]{TOKEN, "wrong", null, ""}) {
            for (boolean available : new boolean[]{true, false}) {
                FormsHttpHandler.EditRoute route =
                        FormsHttpHandler.routeFor(intercept(token), available, new OneShot(TOKEN));

                assertNotEquals(FormsHttpHandler.EditRoute.Decision.NOT_MINE, route.decision(),
                        "token=" + token + " available=" + available
                                + ": an intercept draft carries plaintext, so falling through to "
                                + "any other path would put it on the wire");
            }
        }
    }

    @Test
    @DisplayName("the capability is spent at most once per request")
    void theCapabilityIsSpentOnce() {
        OneShot tokens = new OneShot(TOKEN);
        FormsHttpHandler.routeFor(intercept(TOKEN), true, tokens);

        assertTrue(tokens.calls.get() <= 1,
                "asking twice would spend a second capability the user never minted");
    }
}
