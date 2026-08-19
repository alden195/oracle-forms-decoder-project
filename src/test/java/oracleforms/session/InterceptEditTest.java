package oracleforms.session;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import oracleforms.codec.Rc4Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Mode D: editing a request while the proxy is holding it (architecture &sect;6.12).
 *
 * <p>This is architecture &sect;6.2's {@code "proxied request P, edited to P′"} row — the one the
 * four-stream ledger was designed for and the only one nothing exercised until now. The Repeater
 * case was built first because &sect;6.2 recognised an injection as the same problem with the length
 * going 0 → n; this is that problem at its original length.
 *
 * <p>Both parties hold their own continuous ciphers, as in {@link DivergedForwardingTest}, and the
 * test asserts the property that actually matters: after an edit of <em>any</em> length, the server
 * reads what the user wrote, the client reads every reply, and the conversation keeps working in
 * both directions for the rest of the session.
 */
class InterceptEditTest {

    private static final String SESSION = "intercept-edit-session";
    private static final byte[] KEY = {0x4D, 0x1F, (byte) 0xAE, 0x60, (byte) 0xB2};

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

    /** An ordinary proxied request, forwarded the way {@code FormsHttpHandler} forwards one. */
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

    /**
     * The Mode D path, in the order the extension performs it.
     *
     * <p>Display first — a <em>detached</em> cipher, so looking at a message never moves the ledger
     * — then the edit, then the forward. The server's plaintext is what comes back.
     */
    private byte[] interceptAndEdit(byte[] clientPlaintext, byte[] edited) {
        byte[] fromClient = client.requests.applied(clientPlaintext);

        // What the tab shows. The ledger must be exactly where it was afterwards.
        long before = streams.consumed(StreamLeg.CLIENT_REQUEST);
        byte[] displayed = streams.cipherAt(StreamLeg.CLIENT_REQUEST).applied(fromClient);
        assertArrayEquals(clientPlaintext, displayed,
                "the intercept tab must decode the held message at the client leg's own position");
        assertEquals(before, streams.consumed(StreamLeg.CLIENT_REQUEST),
                "displaying a message must not move the ledger");

        InterceptEditPlan.Result result =
                InterceptEditPlan.edit(streams, edited, fromClient.length, pragma++);
        InterceptEditPlan.Result.Ready ready =
                assertInstanceOf(InterceptEditPlan.Result.Ready.class, result);
        return server.requests.applied(ready.ciphertext());
    }

    @Test
    @DisplayName("a length-changing edit reaches the server, and the client carries on afterwards")
    void lengthChangingEditIsCarriedAcross() {
        assertArrayEquals(ascii("hello"), proxyRequest(ascii("hello")));
        assertArrayEquals(ascii("first reply"), proxyResponse(ascii("first reply")));

        // The user retypes a value and makes the message considerably longer.
        assertArrayEquals(
                ascii("SET USERNAME=administrator"),
                interceptAndEdit(ascii("SET USERNAME=bob"), ascii("SET USERNAME=administrator")));

        assertTrue(streams.diverged(), "a length change must part the two request legs");
        assertTrue(streams.diverged(Direction.REQUEST));
        assertFalse(streams.diverged(Direction.RESPONSE),
                "a request edit must not disturb the response legs, which is why replies still "
                        + "forward unchanged");

        // The whole point: the real client has no idea, and keeps working.
        assertArrayEquals(ascii("the server answers"), proxyResponse(ascii("the server answers")));
        assertArrayEquals(ascii("client keeps talking"), proxyRequest(ascii("client keeps talking")));
        assertArrayEquals(ascii("and is answered"), proxyResponse(ascii("and is answered")));
    }

    @Test
    @DisplayName("a shortening edit is absorbed the same way")
    void shorteningEditIsCarriedAcross() {
        assertArrayEquals(ascii("hello"), proxyRequest(ascii("hello")));

        assertArrayEquals(
                ascii("x"),
                interceptAndEdit(ascii("a much longer original message"), ascii("x")));

        assertTrue(streams.diverged());
        assertArrayEquals(ascii("still fine"), proxyRequest(ascii("still fine")));
        assertArrayEquals(ascii("still answered"), proxyResponse(ascii("still answered")));
    }

    @Test
    @DisplayName("a same-length edit diverges nothing, so later traffic forwards unchanged")
    void sameLengthEditDoesNotDiverge() {
        assertArrayEquals(ascii("hello"), proxyRequest(ascii("hello")));

        assertArrayEquals(ascii("SET FLAG=1"), interceptAndEdit(ascii("SET FLAG=0"), ascii("SET FLAG=1")));

        assertFalse(streams.diverged(),
                "the legs moved by the same amount, so there is nothing to persist and nothing to "
                        + "translate — this is the difference between bisection steps 3-4 and step 5");
        assertArrayEquals(ascii("carries on"), proxyRequest(ascii("carries on")));
        assertArrayEquals(ascii("answered"), proxyResponse(ascii("answered")));
    }

    @Test
    @DisplayName("an unedited intercept is byte-identical to plain forwarding")
    void anUneditedInterceptChangesNothing() {
        proxyRequest(ascii("hello"));

        byte[] plaintext = ascii("unchanged message");
        byte[] fromClient = client.requests.applied(plaintext);
        InterceptEditPlan.Result.Ready ready = assertInstanceOf(
                InterceptEditPlan.Result.Ready.class,
                InterceptEditPlan.edit(streams, plaintext, fromClient.length, pragma++));

        assertArrayEquals(fromClient, ready.ciphertext(),
                "re-encrypting the same plaintext at the same offset must reproduce the client's "
                        + "own bytes; if it does not, the offset is wrong");
        assertFalse(ready.diverged());
        assertArrayEquals(plaintext, server.requests.applied(ready.ciphertext()));
    }

    @Test
    @DisplayName("repeated edits accumulate, and every one of them is readable at the far end")
    void repeatedEditsAccumulate() {
        proxyRequest(ascii("open"));

        assertArrayEquals(ascii("edit one is long"),
                interceptAndEdit(ascii("one"), ascii("edit one is long")));
        assertArrayEquals(ascii("two"), proxyRequest(ascii("two")));
        assertArrayEquals(ascii("3"), interceptAndEdit(ascii("three"), ascii("3")));
        assertArrayEquals(ascii("four"), proxyRequest(ascii("four")));
        assertArrayEquals(ascii("done"), proxyResponse(ascii("done")));

        assertNotEquals(
                streams.consumed(StreamLeg.CLIENT_REQUEST),
                streams.consumed(StreamLeg.SERVER_REQUEST));
    }

    @Test
    @DisplayName("the divergence an edit creates survives being rebuilt from its counters")
    void divergenceSurvivesAReload() {
        proxyRequest(ascii("open"));
        interceptAndEdit(ascii("short"), ascii("a good deal longer than the original"));

        // What the project file would hold, and what a reload rebuilds from it.
        SessionStreams reloaded =
                SessionStreams.resumedAt(SESSION, KEY, streams.positions());

        byte[] fromClient = client.requests.applied(ascii("after the reload"));
        SessionStreams.Forwarded forwarded =
                reloaded.forward(Direction.REQUEST, fromClient, pragma++);
        assertTrue(forwarded.rewritten());
        assertArrayEquals(ascii("after the reload"), server.requests.applied(forwarded.body()));
    }

    @Test
    @DisplayName("editing a message into a NULLPOST sends it cleartext and advances nothing")
    void editingIntoANullPostStaysCleartext() {
        proxyRequest(ascii("open"));

        long serverBefore = streams.consumed(StreamLeg.SERVER_REQUEST);
        byte[] fromClient = client.requests.applied(ascii("a real message"));
        InterceptEditPlan.Result.Ready ready = assertInstanceOf(
                InterceptEditPlan.Result.Ready.class,
                InterceptEditPlan.edit(streams, PragmaBody.NULL_POST, fromClient.length, pragma++));

        assertArrayEquals(PragmaBody.NULL_POST, ready.ciphertext(),
                "the sentinel is written straight to the socket, never through the cipher");
        assertEquals(serverBefore, streams.consumed(StreamLeg.SERVER_REQUEST),
                "so it must contribute nothing to the server's request keystream");
        assertTrue(streams.diverged());
    }

    @Test
    @DisplayName("a NULLPOST the client sent advances its leg by nothing")
    void anInterceptedNullPostCostsTheClientNothing() {
        proxyRequest(ascii("open"));

        long clientBefore = streams.consumed(StreamLeg.CLIENT_REQUEST);
        // The caller passes the *stream* length, which is zero for the sentinel.
        InterceptEditPlan.edit(streams, ascii("something real"), 0, pragma++);

        assertEquals(clientBefore, streams.consumed(StreamLeg.CLIENT_REQUEST));
    }

    @Test
    @DisplayName("unusable inputs are refused, never encrypted at a made-up position")
    void unusableInputsAreRefused() {
        assertInstanceOf(InterceptEditPlan.Result.Refused.class,
                InterceptEditPlan.edit(null, ascii("x"), 4, 5));
        assertInstanceOf(InterceptEditPlan.Result.Refused.class,
                InterceptEditPlan.edit(streams, new byte[0], 4, 5));
        assertInstanceOf(InterceptEditPlan.Result.Refused.class,
                InterceptEditPlan.edit(streams, null, 4, 5));
        assertInstanceOf(InterceptEditPlan.Result.Refused.class,
                InterceptEditPlan.edit(streams, ascii("x"), -1, 5));
        assertInstanceOf(InterceptEditPlan.Result.Refused.class,
                InterceptEditPlan.edit(streams, ascii("x"), 4,
                        StreamReplayer.FIRST_ENCRYPTED_PRAGMA - 1));

        assertFalse(streams.diverged(), "a refusal must not have moved anything");
        assertEquals(0, streams.consumed(StreamLeg.CLIENT_REQUEST));
        assertEquals(0, streams.consumed(StreamLeg.SERVER_REQUEST));
    }

    @Test
    @DisplayName("an edit reports the offset it encrypted at, which is the server's own position")
    void theReportedOffsetIsTheServersPosition() {
        proxyRequest(ascii("twelve bytes"));

        byte[] fromClient = client.requests.applied(ascii("next"));
        InterceptEditPlan.Result.Ready ready = assertInstanceOf(
                InterceptEditPlan.Result.Ready.class,
                InterceptEditPlan.edit(streams, ascii("replacement"), fromClient.length, pragma++));

        assertEquals("twelve bytes".length(), ready.position());
    }
}
