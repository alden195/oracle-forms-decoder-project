package oracleforms.burp.repeater;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import oracleforms.burp.DecodedBodyCache;
import oracleforms.burp.history.PragmaHistorySource;
import oracleforms.session.CookieHeader;
import oracleforms.session.InjectionPlan;
import oracleforms.session.SessionId;
import oracleforms.session.SessionKey;
import oracleforms.session.SessionKeyStore;
import oracleforms.session.SessionStreams;
import oracleforms.session.SessionTail;
import oracleforms.session.StreamGapException;
import oracleforms.session.StreamLeg;
import oracleforms.session.StreamRegistry;

/**
 * Encrypts drafted messages on their way out, and decrypts the replies on their way back.
 *
 * <p>This is the half of the marker contract that lives on the wire (architecture &sect;6.5). It is
 * the <strong>single owner of outbound crypto</strong>, which is the point: the correct keystream
 * offset is not knowable until the request actually leaves, so the editor holds plaintext and this
 * class turns it into ciphertext at the last possible moment.
 *
 * <h2>Fail closed</h2>
 *
 * <p>Every path that cannot produce correct ciphertext ends in
 * {@link RequestToBeSentAction#spoof}: the request never leaves Burp, and the reason appears in
 * Repeater's response pane where the user is already looking. Letting a marked request through
 * unencrypted would put readable FHT — including any credentials in it — on the wire, and letting one
 * through encrypted at a guessed offset would feed the server noise and could take down the session
 * being tested.
 *
 * <h2>Threading</h2>
 *
 * <p>Burp calls this from its own request and response threads, and two sends against one session
 * must not interleave: they would both encrypt at the same offset and each would make the other
 * unreadable. Sends are therefore serialised per session on a small fixed set of stripes — bounded by
 * construction, and over-locking two unrelated sessions costs nothing.
 */
public final class RepeaterSendInterceptor {

    /** Tools whose requests may carry draft markers. Anything else is the tested application. */
    private static final ToolType[] TRUSTED_TOOLS = {
            ToolType.REPEATER, ToolType.INTRUDER, ToolType.EXTENSIONS};

    /** Per-session send locks. Striped so the set cannot grow with the number of sessions. */
    private static final int LOCK_STRIPES = 16;

    /** Sends awaiting their reply. One small record each, dropped as soon as the reply lands. */
    private static final int MAX_PENDING = 64;

    private final SessionKeyStore keyStore;
    private final StreamRegistry registry;
    private final Function<String, PragmaHistorySource> historyForSession;
    private final DecodedBodyCache decoded;
    private final Logging logging;

    private final Object[] locks = new Object[LOCK_STRIPES];
    private final Map<Integer, PendingSend> pending;

    /** What a sent draft needs remembered so its reply can be decrypted when it arrives. */
    private record PendingSend(String sessionId, SendMode mode, long responseOffset, int pragma) {
    }

    public RepeaterSendInterceptor(
            SessionKeyStore keyStore,
            StreamRegistry registry,
            Function<String, PragmaHistorySource> historyForSession,
            DecodedBodyCache decoded,
            Logging logging) {

        this.keyStore = keyStore;
        this.registry = registry;
        this.historyForSession = historyForSession;
        this.decoded = decoded;
        this.logging = logging;
        for (int i = 0; i < LOCK_STRIPES; i++) {
            locks[i] = new Object();
        }
        this.pending = new LinkedHashMap<>(16, 0.75f, false) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<Integer, PendingSend> eldest) {
                return size() > MAX_PENDING;
            }
        };
    }

    /**
     * Handles an outgoing request if it is a draft.
     *
     * @return empty when this is not our business, leaving the caller to carry on
     */
    public Optional<RequestToBeSentAction> intercept(HttpRequestToBeSent request) {
        if (!isMarked(request)) {
            return Optional.empty();
        }

        // Past this point the request is known to carry FHT plaintext and marker headers, and the
        // caller's fallback is `continueWith(request)` -- which would put both on the wire. So every
        // path out of this block has to be a send, a strip or a refusal, and none of them may throw
        // past here. An earlier version left the trust check outside this try, so an exception from
        // `toolSource()` or `strip()` escaped to the handler and the draft went out as plaintext.
        try {
            // Rule 1 of the contract. A marker on proxied traffic was set by the client, and the
            // client is the application under test (BApp criterion 3). Strip it and treat the
            // request as ordinary — never act on it.
            if (!request.toolSource().isFromTool(TRUSTED_TOOLS)) {
                logging.logToError("Oracle Forms: ignoring " + DraftMarkers.SESSION_HEADER
                        + " on a request from " + request.toolSource().toolType()
                        + "; draft markers are only honoured from Repeater, Intruder and extensions.");
                return Optional.of(RequestToBeSentAction.continueWith(DraftMarkers.strip(request)));
            }
            return Optional.of(send(request));
        } catch (RuntimeException e) {
            logging.logToError("Oracle Forms: draft send failed: " + e);
            return Optional.of(refuseSafely(request,
                    "The Oracle Forms decoder failed while preparing this message: " + e));
        }
    }

    /**
     * Whether the request carries draft markers, tolerating a header accessor that misbehaves.
     *
     * <p>Returning false on failure sends the request down the ordinary path untouched, which is the
     * honest answer: if the markers cannot be read then this is not identifiably ours, and a request
     * that is not ours is not one to interfere with.
     */
    private static boolean isMarked(HttpRequestToBeSent request) {
        try {
            return DraftMarkers.isMarked(request);
        } catch (RuntimeException e) {
            return false;
        }
    }

    /**
     * A refusal that cannot itself fail.
     *
     * <p>If even building the explanation goes wrong, the draft is dropped. A dropped request is a
     * confusing result; a draft sent as readable FHT is a disclosure, so there is no contest.
     */
    private RequestToBeSentAction refuseSafely(HttpRequest request, String reason) {
        try {
            return refuse(request, reason);
        } catch (RuntimeException e) {
            logging.logToError("Oracle Forms: could not build a refusal response, dropping the "
                    + "draft rather than sending it unencrypted: " + e);
            return RequestToBeSentAction.drop();
        }
    }

    private RequestToBeSentAction send(HttpRequestToBeSent request) {
        Optional<DraftMarkers> parsed = DraftMarkers.from(request);
        if (parsed.isEmpty()) {
            return refuse(request, "This message is marked as an Oracle Forms draft, but its "
                    + DraftMarkers.SEND_HEADER + " header is missing or is not one of: tail, offset.\n\n"
                    + "Nothing was sent. The send mode is never chosen for you, because the modes "
                    + "differ in whether they act on a live application session.");
        }
        DraftMarkers markers = parsed.get();

        Optional<SessionKey> key = keyStore.get(markers.sessionId());
        if (key.isEmpty()) {
            return refuse(request, "No key is stored for session " + markers.sessionId() + ".\n\n"
                    + "Nothing was sent. Recover the key from the Sessions tab - run a retroactive "
                    + "history scan, or enter it by hand - and send again.");
        }

        byte[] plaintext = request.body().getBytes();
        PragmaHistorySource history = historyForSession.apply(markers.sessionId());

        Prepared prepared;
        synchronized (lockFor(markers.sessionId())) {
            prepared = prepare(markers, key.get(), history, plaintext);
        }
        if (prepared.refusal != null) {
            return refuse(request, prepared.refusal);
        }

        remember(request.messageId(),
                new PendingSend(markers.sessionId(), markers.mode(), prepared.responseOffset,
                        prepared.pragma));

        logging.logToOutput("Oracle Forms: sending " + plaintext.length + " plaintext bytes as pragma "
                + prepared.pragma + " of session " + markers.sessionId()
                + " (" + markers.mode().wireName() + " mode, keystream offset "
                + prepared.position + ")");

        return RequestToBeSentAction.continueWith(
                outgoing(request, markers, history, prepared));
    }

    /** The result of planning, kept separate so the session lock is held for as little as possible. */
    private static final class Prepared {
        byte[] ciphertext;
        int pragma;
        long position;
        long responseOffset;
        String refusal;

        static Prepared refused(String reason) {
            Prepared p = new Prepared();
            p.refusal = reason;
            return p;
        }
    }

    private Prepared prepare(
            DraftMarkers markers, SessionKey key, PragmaHistorySource history, byte[] plaintext) {

        Prepared prepared = new Prepared();
        InjectionPlan.Result result;

        if (markers.mode() == SendMode.TAIL) {
            SessionStreams streams;
            try {
                streams = registry.open(markers.sessionId(), key, history);
            } catch (StreamGapException e) {
                return Prepared.refused(e.getMessage() + "\n\nNothing was sent. Encrypting at a "
                        + "guessed offset would feed the server noise and could end the session you "
                        + "are testing, so the send is refused rather than attempted.");
            }
            prepared.responseOffset = streams.consumed(StreamLeg.SERVER_RESPONSE);
            result = InjectionPlan.atTail(streams, plaintext);
            if (result instanceof InjectionPlan.Result.Ready) {
                // Only after a completed step, never mid-forward -- see StreamRegistry.checkpoint.
                registry.checkpoint(streams);
            }
        } else {
            try {
                prepared.responseOffset =
                        SessionTail.measure(history, markers.originPragma() - 1).responseBytes();
            } catch (StreamGapException e) {
                return Prepared.refused(e.getMessage());
            }
            result = InjectionPlan.atCapturedOffset(
                    history, key.key(), markers.originPragma(), plaintext);
        }

        if (result instanceof InjectionPlan.Result.Refused refused) {
            return Prepared.refused(refused.reason() + "\n\nNothing was sent.");
        }
        InjectionPlan.Result.Ready ready = (InjectionPlan.Result.Ready) result;
        prepared.ciphertext = ready.ciphertext();
        prepared.pragma = ready.pragma();
        prepared.position = ready.position();
        return prepared;
    }

    /**
     * Builds the request that actually goes out: ciphertext body, correct sequence number, refreshed
     * rotating cookie, and no markers.
     *
     * <p>{@code Content-Length} needs no attention. RC4 is length-preserving, so the body is exactly
     * as long as the plaintext Burp already measured.
     */
    private HttpRequest outgoing(
            HttpRequest request, DraftMarkers markers, PragmaHistorySource history,
            Prepared prepared) {

        HttpRequest outgoing = DraftMarkers.strip(request)
                .withBody(ByteArray.byteArray(prepared.ciphertext))
                .withUpdatedHeader("Pragma", Integer.toString(prepared.pragma));

        return withRefreshedRotatingCookie(outgoing, history);
    }

    /**
     * Replaces {@code JSESSIONID_FORMS} with the value the client most recently used.
     *
     * <p>Only that one cookie, and only if it is already present. The rest of the header is whatever
     * the user typed into Repeater, and it is theirs.
     */
    private HttpRequest withRefreshedRotatingCookie(
            HttpRequest request, PragmaHistorySource history) {

        try {
            if (!request.hasHeader("Cookie")) {
                return request;
            }
            Optional<String> latest = history.latestCookieHeader()
                    .flatMap(header -> CookieHeader.value(header, SessionId.ROTATING_COOKIE_NAME));
            if (latest.isEmpty()) {
                return request;
            }
            String current = request.headerValue("Cookie");
            String refreshed =
                    CookieHeader.withValue(current, SessionId.ROTATING_COOKIE_NAME, latest.get());
            return refreshed.equals(current) ? request : request.withUpdatedHeader("Cookie", refreshed);
        } catch (RuntimeException e) {
            // A cookie we could not refresh is a routing risk, not a correctness one. Say so and
            // send what the user wrote.
            logging.logToError("Oracle Forms: could not refresh " + SessionId.ROTATING_COOKIE_NAME
                    + ": " + e);
            return request;
        }
    }

    /**
     * Decrypts the reply to a draft we sent, if this is one.
     *
     * <p>Returning a value also tells the caller to keep its hands off this response: the ledger has
     * already been advanced here, and advancing it a second time from the ordinary
     * observe-and-forward path would put the response stream a whole message ahead.
     *
     * @return empty when this response is not ours
     */
    public Optional<ResponseReceivedAction> interceptResponse(HttpResponseReceived response) {
        PendingSend sent;
        synchronized (pending) {
            sent = pending.remove(response.messageId());
        }
        if (sent == null) {
            return Optional.empty();
        }

        try {
            byte[] ciphertext = response.body().getBytes();
            if (ciphertext.length == 0) {
                return Optional.of(ResponseReceivedAction.continueWith(response));
            }

            byte[] plaintext;
            synchronized (lockFor(sent.sessionId())) {
                plaintext = decryptReply(sent, ciphertext);
            }
            if (plaintext != null) {
                // Repeater responses never reach proxy history, so the replay path cannot find
                // them. Keying the cache on the ciphertext lets the response editor pick this up
                // without knowing anything about how it got here (architecture §6.5).
                decoded.put(ciphertext, plaintext);
            }
        } catch (RuntimeException e) {
            logging.logToError("Oracle Forms: could not decrypt the reply to pragma "
                    + sent.pragma() + ": " + e);
        }
        return Optional.of(ResponseReceivedAction.continueWith(response));
    }

    private byte[] decryptReply(PendingSend sent, byte[] ciphertext) {
        if (sent.mode() == SendMode.TAIL) {
            Optional<SessionStreams> streams = registry.peek(sent.sessionId());
            if (streams.isEmpty()) {
                return null;
            }
            byte[] plaintext = streams.get().apply(StreamLeg.SERVER_RESPONSE, ciphertext);
            registry.checkpoint(streams.get());
            return plaintext;
        }

        // Offset mode never touched the ledger, so the reply is decrypted with a detached cipher at
        // the position the server would have been at when it sent the original.
        return keyStore.get(sent.sessionId())
                .map(key -> SessionStreams.atOrigin(sent.sessionId(), key.key())
                        .cipherAtOffset(sent.responseOffset())
                        .applied(ciphertext))
                .orElse(null);
    }

    private void remember(int messageId, PendingSend sent) {
        synchronized (pending) {
            pending.put(messageId, sent);
        }
    }

    private Object lockFor(String sessionId) {
        return locks[Math.floorMod(sessionId.hashCode(), LOCK_STRIPES)];
    }

    /**
     * Answers a refused draft with a synthetic response, so the request never leaves Burp.
     *
     * <p>The status code is deliberately not a real one: a fabricated 500 could be mistaken for the
     * server's own answer, which is the last thing a refusal should look like.
     */
    private RequestToBeSentAction refuse(HttpRequest request, String reason) {
        return RequestToBeSentAction.spoof(HttpResponse.httpResponse(
                ByteArray.byteArray(refusalBytes(hostOf(request), reason))));
    }

    /**
     * The refusal response, as the exact bytes that will be shown.
     *
     * <p>Assembled as bytes rather than handed to Burp as a string, because the two are not the same
     * length. An earlier version computed {@code Content-Length} from the UTF-8 encoding and passed
     * the message as a {@code String}, which Burp encodes as Latin-1: every multi-byte character
     * shrank on the way out and the header over-declared the body. Two em dashes in one of these
     * messages were enough to leave a live refusal claiming four bytes it never sent, which a client
     * honouring {@code Content-Length} waits forever for.
     *
     * <p>{@code reason} can carry a session id taken from a request header, so the length must be
     * derived from the bytes rather than assumed to be the character count (BApp criterion 3).
     * Package-private so the invariant can be tested directly.
     */
    static byte[] refusalBytes(String host, String reason) {
        byte[] body = ("Oracle Forms Decoder refused to send this message.\n\n"
                + reason + "\n\n"
                + "-- \nThis response was generated by the Oracle Forms Decoder extension. The "
                + "request was not sent to " + host + ".\n")
                .getBytes(StandardCharsets.UTF_8);

        byte[] head = ("HTTP/1.1 599 Not Sent - Oracle Forms Decoder\r\n"
                + "Content-Type: text/plain; charset=utf-8\r\n"
                + "Content-Length: " + body.length + "\r\n"
                + "\r\n")
                .getBytes(StandardCharsets.US_ASCII);

        byte[] raw = new byte[head.length + body.length];
        System.arraycopy(head, 0, raw, 0, head.length);
        System.arraycopy(body, 0, raw, head.length, body.length);
        return raw;
    }

    private static String hostOf(HttpRequest request) {
        try {
            return request.httpService() == null ? "the server" : request.httpService().host();
        } catch (RuntimeException e) {
            return "the server";
        }
    }

    /** Drops every pending send. Called on unload (BApp criterion 6). */
    public void shutdown() {
        synchronized (pending) {
            pending.clear();
        }
    }
}
