package oracleforms.burp.handler;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.logging.Logging;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.concurrent.ConcurrentHashMap;
import oracleforms.burp.FormsDetector;
import oracleforms.burp.repeater.DraftMarkers;
import oracleforms.burp.repeater.RepeaterSendInterceptor;
import oracleforms.session.Direction;
import oracleforms.session.Handshake;
import oracleforms.session.KeyDerivation;
import oracleforms.session.KeySource;
import oracleforms.session.PragmaBody;
import oracleforms.session.SessionKey;
import oracleforms.session.SessionKeyStore;
import oracleforms.session.SessionStreams;
import oracleforms.session.StreamRegistry;
import oracleforms.session.StreamReplayer;

/**
 * Watches proxied traffic and captures session keys from Pragma 1 handshakes.
 *
 * <p><strong>Key capture is the only work this handler does.</strong> No decryption, no parsing, no
 * formatting. That is a deliberate departure from the reference implementation, which ran its entire
 * decode-and-format pipeline inside the proxy listener and so put every Forms message's cost on the
 * hot path (architecture &sect;7.7, BApp criterion 5). Everything expensive here happens later, on a
 * background executor, and only for messages a user actually opens.
 *
 * <p>The work per message is: one substring test on the path, and for the rare Pragma 1, two 8-byte
 * body reads and a key derivation.
 */
public final class FormsHttpHandler implements HttpHandler {

    private final SessionKeyStore keyStore;
    private final KeyDerivation derivation;
    private final Logging logging;
    private final boolean annotateHistory;
    private final RepeaterSendInterceptor interceptor;
    private final StreamRegistry streams;

    /**
     * Client randoms seen on Pragma 1 requests, awaiting their response. Bounded: an entry is
     * removed as soon as its response arrives, and the map is cleared on unload. A handshake whose
     * response never arrives leaves one 4-byte entry, so the worst case is one per abandoned
     * session rather than anything proportional to traffic.
     */
    private final Map<String, Integer> pendingClientRandoms = new ConcurrentHashMap<>();

    /** Guards {@link #pendingClientRandoms} against a pathological number of dead handshakes. */
    private static final int MAX_PENDING = 512;

    public FormsHttpHandler(
            SessionKeyStore keyStore,
            KeyDerivation derivation,
            Logging logging,
            boolean annotateHistory,
            RepeaterSendInterceptor interceptor,
            StreamRegistry streams) {
        this.keyStore = keyStore;
        this.derivation = derivation;
        this.logging = logging;
        this.annotateHistory = annotateHistory;
        this.interceptor = interceptor;
        this.streams = streams;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        try {
            // A drafted message carries plaintext and must be encrypted before it goes anywhere.
            // This runs first because such a request must never fall through to the ordinary paths.
            if (interceptor != null) {
                Optional<RequestToBeSentAction> handled = interceptor.intercept(request);
                if (handled.isPresent()) {
                    return handled.get();
                }
            }

            Optional<FormsDetector.FormsTarget> target = FormsDetector.detect(request);
            if (target.isEmpty()) {
                return RequestToBeSentAction.continueWith(request);
            }
            FormsDetector.FormsTarget forms = target.get();

            trackForwarded(request, forms, Direction.REQUEST, request.body().getBytes());

            if (forms.pragma() == Handshake.HANDSHAKE_PRAGMA) {
                OptionalInt clientRandom = Handshake.clientRandom(request.body().getBytes());
                if (clientRandom.isPresent() && pendingClientRandoms.size() < MAX_PENDING) {
                    pendingClientRandoms.put(forms.sessionId(), clientRandom.getAsInt());
                }
            }

            if (annotateHistory) {
                return RequestToBeSentAction.continueWith(
                        request, annotationFor(forms, request.body().getBytes()));
            }
        } catch (RuntimeException e) {
            // Never let an extension bug break the user's proxy, and never swallow it silently
            // either -- the reference did exactly that at the top of its listener (§7.10).
            logging.logToError("Oracle Forms: error handling request: " + e);

            // ...but "carry on unchanged" is the wrong recovery for a draft, whose body is FHT
            // plaintext and whose markers have not been stripped. The interceptor is built not to
            // throw for exactly this reason; this is the second line, so that the fail-closed
            // guarantee in architecture §6.5 does not rest on one method's error handling.
            if (isDraft(request)) {
                logging.logToError("Oracle Forms: dropping a draft rather than sending its "
                        + "plaintext after an internal error.");
                return RequestToBeSentAction.drop();
            }
        }
        return RequestToBeSentAction.continueWith(request);
    }

    /** Whether a request carries draft markers, never throwing on the way to an answer. */
    private static boolean isDraft(HttpRequestToBeSent request) {
        try {
            return DraftMarkers.isMarked(request);
        } catch (RuntimeException e) {
            // Cannot tell. Treat it as a draft: the cost of a wrong "yes" is a dropped request,
            // and the cost of a wrong "no" is plaintext on the wire.
            return true;
        }
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        try {
            if (interceptor != null) {
                Optional<ResponseReceivedAction> handled = interceptor.interceptResponse(response);
                if (handled.isPresent()) {
                    // The reply to a message we sent. Its effect on the ledger is already recorded,
                    // and doing it again here would put the response stream a message ahead.
                    return handled.get();
                }
            }

            Optional<FormsDetector.FormsTarget> target =
                    FormsDetector.detect(response.initiatingRequest());
            if (target.isEmpty()) {
                return ResponseReceivedAction.continueWith(response);
            }
            FormsDetector.FormsTarget forms = target.get();

            trackForwarded(response, forms, Direction.RESPONSE, response.body().getBytes());

            if (forms.pragma() == Handshake.HANDSHAKE_PRAGMA) {
                captureKey(forms.sessionId(), response);
            }
        } catch (RuntimeException e) {
            logging.logToError("Oracle Forms: error handling response: " + e);
        }
        return ResponseReceivedAction.continueWith(response);
    }

    /**
     * Completes a handshake: pairs the stashed client random with the server random and stores the
     * derived key.
     */
    private void captureKey(String sessionId, HttpResponseReceived response) {
        Integer clientRandom = pendingClientRandoms.remove(sessionId);
        if (clientRandom == null) {
            return;
        }
        OptionalInt serverRandom = Handshake.serverRandom(response.body().getBytes());
        if (serverRandom.isEmpty()) {
            logging.logToError("Oracle Forms: Pragma 1 response for session " + sessionId
                    + " has no Mate magic; no key derived");
            return;
        }

        byte[] key = derivation.deriveKey(clientRandom, serverRandom.getAsInt());
        long now = System.currentTimeMillis();

        // Preserve firstSeen if we already knew this session.
        long firstSeen = keyStore.get(sessionId).map(SessionKey::firstSeen).orElse(now);

        keyStore.put(new SessionKey(
                sessionId, key, hostOf(response), firstSeen, now, "", KeySource.DERIVED));

        logging.logToOutput("Oracle Forms: captured key for session " + sessionId);
    }

    private static String hostOf(HttpResponseReceived response) {
        try {
            return response.initiatingRequest().httpService().host();
        } catch (RuntimeException e) {
            return "";
        }
    }

    /**
     * Colours and comments Forms traffic so it is findable in a large project. Purely cosmetic, and
     * cheap — it builds a short string and sets two fields.
     */
    private Annotations annotationFor(FormsDetector.FormsTarget forms, byte[] body) {
        if (PragmaBody.isNullPost(body)) {
            // Labelling a NULLPOST "encrypted" sends the reader looking for ciphertext that was
            // never there: it is the client's cleartext "nothing to send, give me the rest".
            return Annotations.annotations(
                    "Oracle Forms pragma " + forms.pragma() + " (NULLPOST, no payload)",
                    HighlightColor.CYAN);
        }
        String note = "Oracle Forms pragma " + forms.pragma()
                + (forms.isEncrypted() ? " (encrypted)" : " (cleartext)");
        return Annotations.annotations(note, HighlightColor.CYAN);
    }

    /**
     * Keeps an open session ledger level with the traffic the real client is still generating.
     *
     * <p>Without this, a session whose streams were opened for a Repeater send goes stale the moment
     * the client sends anything else, and the next send would encrypt at an offset the server left
     * behind — the failure mode the whole design exists to avoid.
     *
     * <p><strong>On the hot path budget.</strong> Architecture &sect;5 says key capture is the only
     * work done here, and this is a deliberate, bounded addition to that. It costs a hash lookup for
     * every Forms message and nothing at all for anything else; the RC4 skip only happens for a
     * session the user has actually opened a ledger for, which means one they have already chosen to
     * send into. Sessions nobody sends to never reach the second line of this method.
     */
    private void trackForwarded(
            Object message, FormsDetector.FormsTarget forms, Direction direction, byte[] body) {

        if (streams == null || !forms.isEncrypted()) {
            return;
        }
        // Only the real client's traffic moves both legs together. A hand-crafted Repeater resend of
        // captured ciphertext also reaches the server, but at an offset nobody can know, so it is
        // deliberately not modelled -- see architecture §6.9.
        if (!isFromProxy(message)) {
            return;
        }
        Optional<SessionStreams> open = streams.peek(forms.sessionId());
        if (open.isEmpty()) {
            return;
        }
        open.get().observeUnmodified(direction, body, forms.pragma());
    }

    private static boolean isFromProxy(Object message) {
        try {
            if (message instanceof HttpRequestToBeSent request) {
                return request.toolSource().isFromTool(ToolType.PROXY);
            }
            if (message instanceof HttpResponseReceived response) {
                return response.toolSource().isFromTool(ToolType.PROXY);
            }
        } catch (RuntimeException e) {
            return false;
        }
        return false;
    }

    /** Releases the handshake map. Called on unload (BApp criterion 6). */
    public void shutdown() {
        pendingClientRandoms.clear();
    }
}
