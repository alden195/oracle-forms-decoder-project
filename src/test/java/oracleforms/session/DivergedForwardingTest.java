package oracleforms.session;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import oracleforms.codec.Rc4Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * What the proxy has to do to the <em>next</em> message after an injection.
 *
 * <p>{@link SessionStreamsTest} proves the four-stream model works when the proxy translates each
 * forwarded message between its two cipher relationships. This class tests the thing that actually
 * decides whether a live session survives: <strong>that the translation happens at all.</strong>
 *
 * <p>The distinction matters because the two are easy to conflate. A ledger that merely
 * <em>counts</em> the bytes on four legs is not a four-stream proxy — it is a four-column
 * spreadsheet. Once {@link StreamLeg#CLIENT_REQUEST} and {@link StreamLeg#SERVER_REQUEST} sit at
 * different offsets, forwarding the client's ciphertext unchanged hands the server bytes encrypted
 * at an offset it is no longer at, and the Forms runtime answers {@code FRM-93618} (architecture
 * &sect;6.11).
 *
 * <p>So {@link #forwardingVerbatimAfterAnInjectionBreaksTheServer} pins the failure down, and
 * everything else checks {@link SessionStreams#forward} repairs it.
 */
class DivergedForwardingTest {

    private static final String SESSION = "diverged-forwarding-session";
    private static final byte[] KEY = {0x71, 0x0C, (byte) 0xAE, (byte) 0x93, 0x2E};

    /** One end of the conversation, holding the two continuous streams the protocol gives it. */
    private static final class Party {
        final Rc4Stream requests = new Rc4Stream(KEY);
        final Rc4Stream responses = new Rc4Stream(KEY);
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    private final Party client = new Party();
    private final Party server = new Party();
    private final SessionStreams streams = SessionStreams.atOrigin(SESSION, KEY);

    private int pragma = StreamReplayer.FIRST_ENCRYPTED_PRAGMA;

    /**
     * One ordinary proxied request, handled the way {@code FormsHttpHandler} handles it: the ledger
     * is told about the message and whatever it hands back is what goes to the server.
     *
     * @return the plaintext the server ends up reading
     */
    private byte[] proxyRequest(byte[] plaintext) {
        byte[] fromClient = client.requests.applied(plaintext);
        SessionStreams.Forwarded forwarded =
                streams.forward(Direction.REQUEST, fromClient, pragma++);
        return server.requests.applied(forwarded.body());
    }

    /** The same for a response travelling the other way. */
    private byte[] proxyResponse(byte[] plaintext) {
        byte[] fromServer = server.responses.applied(plaintext);
        SessionStreams.Forwarded forwarded =
                streams.forward(Direction.RESPONSE, fromServer, pragma);
        return client.responses.applied(forwarded.body());
    }

    /** A Repeater send: it reaches the server, and the real client never learns of it. */
    private byte[] inject(byte[] plaintext) {
        InjectionPlan.Result.Ready ready =
                (InjectionPlan.Result.Ready) InjectionPlan.atTail(streams, plaintext);
        return server.requests.applied(ready.ciphertext());
    }

    /** The reply to an injected message: consumed by the extension, never forwarded to the client. */
    private void consumeInjectedReply(byte[] plaintext) {
        streams.apply(StreamLeg.SERVER_RESPONSE, server.responses.applied(plaintext));
    }

    private void settle(int exchanges) {
        for (int i = 0; i < exchanges; i++) {
            proxyRequest(ascii("client says " + i));
            proxyResponse(ascii("server answers " + i));
        }
    }

    @Test
    @DisplayName("forwarding verbatim after an injection is what feeds the runtime garbage")
    void forwardingVerbatimAfterAnInjectionBreaksTheServer() {
        settle(5);
        inject(ascii("an injected message from Repeater"));

        // What the old handler did: advance the counters, forward the client's bytes untouched.
        byte[] next = ascii("the client carries on, knowing nothing");
        byte[] fromClient = client.requests.applied(next);
        streams.observeUnmodified(Direction.REQUEST, fromClient, pragma);

        assertNotEquals(
                new String(next, StandardCharsets.US_ASCII),
                new String(server.requests.applied(fromClient), StandardCharsets.US_ASCII),
                "if this ever passes, the premise of architecture §6.2 is wrong: forwarding "
                        + "client-side ciphertext unchanged would already be readable by a server "
                        + "whose cipher an injection has moved on");
    }

    @Test
    @DisplayName("the live client keeps working across an injection when the proxy translates")
    void translationKeepsTheLiveClientWorking() {
        settle(5);

        byte[] injected = ascii("an injected message from Repeater");
        assertArrayEquals(injected, inject(injected), "the server must read the injected message");
        consumeInjectedReply(ascii("the reply to the injected message"));

        assertTrue(streams.diverged(), "an injection must part the two sides");

        // The client knows nothing of any of it and simply carries on.
        for (int i = 0; i < 10; i++) {
            byte[] request = ascii("client request after the injection " + i);
            assertArrayEquals(request, proxyRequest(request),
                    "the server could not read the client's message " + i);

            byte[] response = ascii("server response after the injection " + i);
            assertArrayEquals(response, proxyResponse(response),
                    "the client could not read the server's message " + i);
        }
    }

    @Test
    @DisplayName("several injections interleaved with live traffic all land, both ways")
    void repeatedInjectionsInterleavedWithLiveTraffic() {
        settle(3);
        for (int round = 0; round < 4; round++) {
            byte[] injected = ascii("injection number " + round);
            assertArrayEquals(injected, inject(injected));
            consumeInjectedReply(ascii("reply " + round));

            byte[] request = ascii("live traffic in round " + round);
            assertArrayEquals(request, proxyRequest(request));
            byte[] response = ascii("live answer in round " + round);
            assertArrayEquals(response, proxyResponse(response));
        }
    }

    @Test
    @DisplayName("before any divergence nothing is rewritten, so the hot path stays free")
    void undivergedTrafficIsNotRewritten() {
        byte[] plaintext = ascii("an ordinary message");
        byte[] fromClient = client.requests.applied(plaintext);

        SessionStreams.Forwarded forwarded = streams.forward(Direction.REQUEST, fromClient, 3);

        assertFalse(forwarded.rewritten(),
                "an undiverged session's bytes must be forwarded untouched: the two legs share a "
                        + "keystream position, so translating would return the input and cost two "
                        + "RC4 passes for nothing");
        assertArrayEquals(fromClient, forwarded.body());
        assertEquals(fromClient.length, streams.consumed(StreamLeg.CLIENT_REQUEST));
        assertEquals(fromClient.length, streams.consumed(StreamLeg.SERVER_REQUEST));
    }

    @Test
    @DisplayName("a NULLPOST is forwarded cleartext and consumes no keystream, diverged or not")
    void nullPostSurvivesDivergence() {
        settle(2);
        inject(ascii("something injected"));

        long before = streams.consumed(StreamLeg.SERVER_REQUEST);
        SessionStreams.Forwarded forwarded =
                streams.forward(Direction.REQUEST, PragmaBody.NULL_POST.clone(), pragma++);

        assertFalse(forwarded.rewritten(), "a NULLPOST never passes through a cipher");
        assertArrayEquals(PragmaBody.NULL_POST, forwarded.body());
        assertEquals(before, streams.consumed(StreamLeg.SERVER_REQUEST),
                "advancing over a NULLPOST's eight bytes desynchronises every later request");
    }

    @Test
    @DisplayName("a translated session survives being rebuilt from its four counters")
    void translationSurvivesAReload() {
        settle(4);
        inject(ascii("injected before the reload"));
        consumeInjectedReply(ascii("its reply"));

        // The extension is unloaded and comes back with only what the project file held.
        SessionStreams resumed = SessionStreams.resumedAt(SESSION, KEY, streams.positions());

        byte[] request = ascii("the first message after the reload");
        byte[] fromClient = client.requests.applied(request);
        SessionStreams.Forwarded forwarded = resumed.forward(Direction.REQUEST, fromClient, pragma);

        assertTrue(forwarded.rewritten(), "a resumed diverged ledger must still translate");
        assertArrayEquals(request, server.requests.applied(forwarded.body()),
                "the server could not read the client's first message after an extension reload");
    }
}
