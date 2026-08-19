package oracleforms.burp.handler;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;
import oracleforms.burp.FormsDetector;
import oracleforms.burp.repeater.DraftMarkers;
import oracleforms.burp.repeater.RepeaterSendInterceptor;
import oracleforms.burp.proxy.InterceptEditService;
import oracleforms.burp.repeater.SendMode;
import oracleforms.session.Direction;
import oracleforms.session.Handshake;
import oracleforms.session.InterceptEditPlan;
import oracleforms.session.KeyDerivation;
import oracleforms.session.KeySource;
import oracleforms.session.PragmaBody;
import oracleforms.session.SessionKey;
import oracleforms.session.SessionKeyStore;
import oracleforms.session.SessionKey;
import oracleforms.session.SessionStreams;
import oracleforms.session.StreamLeg;
import oracleforms.session.StreamPositionUnknownException;
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

    /** Present only when Mode D is wired; null leaves the handler exactly as it was. */
    private final InterceptEditService interceptEdits;

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
        this(keyStore, derivation, logging, annotateHistory, interceptor, streams, null);
    }

    public FormsHttpHandler(
            SessionKeyStore keyStore,
            KeyDerivation derivation,
            Logging logging,
            boolean annotateHistory,
            RepeaterSendInterceptor interceptor,
            StreamRegistry streams,
            InterceptEditService interceptEdits) {
        this.keyStore = keyStore;
        this.derivation = derivation;
        this.logging = logging;
        this.annotateHistory = annotateHistory;
        this.interceptor = interceptor;
        this.streams = streams;
        this.interceptEdits = interceptEdits;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        try {
            // Mode D goes first, ahead of even the Repeater interceptor, and the order is a safety
            // property rather than a preference. An intercept draft carries FHT *plaintext* and
            // arrives from the Proxy, so the interceptor's own trust rule would classify it as a
            // client-set marker, strip the headers and forward it -- putting readable FHT on the
            // wire, which is precisely what architecture §6.5 rule 3 forbids. Whoever handles a
            // marked request has to be the one that owns its body.
            Optional<RequestToBeSentAction> edited = interceptEdit(request);
            if (edited.isPresent()) {
                return edited.get();
            }

            // A drafted message carries plaintext and must be encrypted before it goes anywhere.
            // This runs before the ordinary paths for the same reason.
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

            byte[] body = request.body().getBytes();
            byte[] translated = trackForwarded(request, forms, Direction.REQUEST, body);
            HttpRequest outgoing = translated == null
                    ? request : request.withBody(ByteArray.byteArray(translated));

            if (forms.pragma() == Handshake.HANDSHAKE_PRAGMA) {
                OptionalInt clientRandom = Handshake.clientRandom(body);
                if (clientRandom.isPresent() && pendingClientRandoms.size() < MAX_PENDING) {
                    pendingClientRandoms.put(forms.sessionId(), clientRandom.getAsInt());
                }
            }

            if (annotateHistory) {
                return RequestToBeSentAction.continueWith(outgoing, annotationFor(forms, body));
            }
            return RequestToBeSentAction.continueWith(outgoing);
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

    /**
     * Re-encrypts a request the user edited in the Intercept tab, or drops it (architecture
     * &sect;6.12).
     *
     * <p>The markers here arrive <em>from the Proxy</em>, which rule 1 of &sect;6.5 otherwise
     * forbids honouring: a marker on proxied traffic was put there by the client, and the client is
     * the application under test. The rule is not relaxed — what is trusted is the single-use token
     * this extension minted and has never put on the wire, and a marker without a valid one falls
     * through to the ordinary path and is stripped there like any other client-set header.
     *
     * <h2>Failing closed means dropping</h2>
     *
     * <p>There is no {@code spoof} on the proxy path, so a refusal cannot be explained to the client
     * at all. Sending nothing is the only answer that never lets a wrong outcome look like a right
     * one — the alternative, forwarding the client's original bytes, would silently discard the edit
     * and report success. The cost is real and is recorded in &sect;6.9: a dropped request will most
     * likely end the session. It is made rare by checking the key, the ledger and the offset before
     * the edit was ever offered, not by softening what happens here.
     *
     * @return the action to take, or empty when this is not an in-flight edit
     */
    /**
     * What must happen to a request, decided from its headers alone.
     *
     * <p>Split out from {@link #interceptEdit} and kept free of any Burp <em>object</em> so it can be
     * driven directly by a test: {@code RequestToBeSentAction}'s factories need a running Burp, so
     * a test that went through the handler could not assert on what came back. The decision is the
     * part worth pinning — it is where a fall-through would put plaintext on the wire.
     *
     * @param decision what to do
     * @param reason   why, when the answer is {@link Decision#DROP}; shown in the log
     */
    record EditRoute(Decision decision, String reason) {

        enum Decision {
            /** Not an in-flight edit. The ordinary paths own it. */
            NOT_MINE,
            /** An authorised in-flight edit: encrypt it at the session's live position. */
            ENCRYPT,
            /** Claimed but not honourable. The body is plaintext, so it must not be forwarded. */
            DROP
        }

        static EditRoute notMine() {
            return new EditRoute(Decision.NOT_MINE, "");
        }

        static EditRoute encrypt() {
            return new EditRoute(Decision.ENCRYPT, "");
        }

        static EditRoute drop(String reason) {
            return new EditRoute(Decision.DROP, reason);
        }
    }

    /**
     * Routes a request, spending its capability if it has a valid one.
     *
     * <p><strong>The invariant this exists to hold: a request carrying intercept markers is never
     * {@code NOT_MINE}.</strong> Such a body is FHT plaintext by construction, so any answer that
     * let it continue down another path — the Repeater interceptor, which would strip the markers
     * and forward it, or the ordinary forwarding path, which would treat plaintext as ciphertext —
     * would put decoded traffic, credentials included, on the wire.
     *
     * @param spendToken consumes a capability, returning whether it was valid. Passed in rather than
     *                   reached for, so a test can drive every branch of the truth table
     */
    static EditRoute routeFor(
            Optional<DraftMarkers> markers, boolean available, Predicate<String> spendToken) {

        if (markers.isEmpty() || markers.get().mode() != SendMode.INTERCEPT) {
            return EditRoute.notMine();
        }
        if (!available) {
            return EditRoute.drop("the in-flight edit path is not available in this build of the "
                    + "extension");
        }
        // Spent here and nowhere else. An invalid capability is dropped rather than forwarded, which
        // covers three cases that cannot be told apart from the outside and all want the same
        // answer: the extension was reloaded between the edit and the Forward, so the token that
        // authorised it no longer exists; Burp called this handler twice and it was already spent;
        // or the application under test invented the markers itself, which rule 1 of §6.5 exists to
        // catch. Only the last is an attack, but forwarding is unsafe in the first two and
        // pointless in the third.
        if (!spendToken.test(markers.get().token())) {
            return EditRoute.drop("this edit carried no capability this extension recognises, so it "
                    + "could not be authorised. Either the extension was reloaded since the request "
                    + "was converted (a token does not survive that), or these markers were not put "
                    + "there by the Oracle Forms tab at all.");
        }
        return EditRoute.encrypt();
    }

    private Optional<RequestToBeSentAction> interceptEdit(HttpRequestToBeSent request) {

        Optional<DraftMarkers> markers = DraftMarkers.from(request);
        boolean available = interceptEdits != null && streams != null;
        EditRoute route = routeFor(markers, available,
                token -> interceptEdits != null && interceptEdits.consumeToken(token));

        if (route.decision() == EditRoute.Decision.NOT_MINE) {
            return Optional.empty();
        }
        DraftMarkers draft = markers.get();
        if (route.decision() == EditRoute.Decision.DROP) {
            return Optional.of(dropEdit(draft, route.reason()));
        }

        Optional<FormsDetector.FormsTarget> target = FormsDetector.detect(request);
        if (target.isEmpty() || !target.get().isEncrypted()) {
            return Optional.of(dropEdit(draft,
                    "this no longer looks like an encrypted Oracle Forms message, so there is no "
                            + "keystream position to encrypt it at"));
        }
        FormsDetector.FormsTarget forms = target.get();

        byte[] plaintext = request.body().getBytes();
        SessionKey key = keyStore.get(draft.sessionId()).orElse(null);
        if (key == null) {
            return Optional.of(dropEdit(draft,
                    "no key is stored for session " + draft.sessionId() + " any more"));
        }

        SessionStreams session;
        try {
            // Opened at display time, so this is a cache hit; it is repeated because a reload or an
            // eviction between the two is possible, and encrypting without a ledger is not. The
            // pragma goes with it so that a rebuild lands *before* this message rather than at the
            // session's tail -- proxy history already holds the request being forwarded, and a tail
            // would count it (architecture §6.12).
            //
            // On a miss this walks the session's captured traffic on a Burp request thread, which
            // §5's hot-path budget otherwise forbids. It is reachable only when the ledger was
            // evicted or the extension reloaded between the edit and the Forward, and the
            // alternative on that path is a dropped request -- which ends the application's
            // session. Correctness wins over the thread it runs on, once.
            session = interceptEdits.openLedger(draft.sessionId(), key, forms.pragma());
        } catch (StreamPositionUnknownException e) {
            return Optional.of(dropEdit(draft, e.getMessage()));
        }

        // The ledger must still be where it was when this edit was decoded.
        //
        // This enforces the assumption architecture §6.12 flagged and could not verify: that a Forms
        // client has at most one request in flight per session. If a second one went by while this
        // was being edited, the forwarding path advanced the client's leg past it, the plaintext in
        // this tab was decoded against an offset the session has left behind, and encrypting the
        // edit now would put the wrong bytes on the wire. Turning a documented assumption into a
        // checked one costs a comparison.
        long actual = session.consumed(StreamLeg.CLIENT_REQUEST);
        if (draft.expectedPosition() >= 0 && draft.expectedPosition() != actual) {
            return Optional.of(dropEdit(draft, "this edit was decoded against keystream offset "
                    + draft.expectedPosition() + ", but the session has since moved to " + actual
                    + " -- something else on this session was forwarded while the request was being "
                    + "edited. The decode this edit was made against no longer describes the "
                    + "session, so it cannot be encrypted correctly."));
        }

        InterceptEditPlan.Result result = InterceptEditPlan.edit(
                session, plaintext, draft.originalLength(), forms.pragma());

        if (result instanceof InterceptEditPlan.Result.Refused refused) {
            return Optional.of(dropEdit(draft, refused.reason()));
        }
        InterceptEditPlan.Result.Ready ready = (InterceptEditPlan.Result.Ready) result;

        // Only once the edit is committed, and only if the legs have actually parted company. A
        // same-length edit diverges nothing and needs no project-file write.
        streams.checkpoint(session);

        logging.logToOutput("Oracle Forms: forwarding an edited pragma " + forms.pragma()
                + " of session " + draft.sessionId() + " -- " + plaintext.length
                + " plaintext bytes encrypted at keystream offset " + ready.position()
                + ", in place of the client's " + draft.originalLength() + " bytes"
                + (ready.diverged()
                        ? ". The session has diverged; it now depends on this extension staying "
                                + "loaded and seeing every message for the rest of its life."
                        : ". Same length, so nothing diverged."));

        // The markers come off here, on the one path that succeeds; every other path out of this
        // method either drops the request or leaves it to be stripped by the ordinary route.
        return Optional.of(RequestToBeSentAction.continueWith(
                DraftMarkers.strip(request).withBody(ByteArray.byteArray(ready.ciphertext()))));
    }

    /**
     * Refuses an in-flight edit by dropping it, saying why as loudly as the API allows.
     *
     * <p>The log is the only channel available: the client gets a dead connection either way, and
     * there is nowhere on the proxy path to put an explanation where the user is already looking.
     */
    private RequestToBeSentAction dropEdit(DraftMarkers draft, String reason) {
        logging.logToError("Oracle Forms: DROPPED an edited request for session "
                + draft.sessionId() + " rather than sending it. " + reason
                + "\n\nNothing was sent, because the alternatives are worse: forwarding the "
                + "client's original bytes would discard your edit and report success, and there is "
                + "no way to explain a refusal to a Forms client. The application's session has "
                + "most likely ended and will need restarting.");
        return RequestToBeSentAction.drop();
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

            byte[] translated =
                    trackForwarded(response, forms, Direction.RESPONSE, response.body().getBytes());

            if (forms.pragma() == Handshake.HANDSHAKE_PRAGMA) {
                captureKey(forms.sessionId(), response);
            }
            if (translated != null) {
                return ResponseReceivedAction.continueWith(
                        response.withBody(ByteArray.byteArray(translated)));
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
     * Carries a proxied message across the session's two cipher relationships, and keeps the ledger
     * level with the traffic the real client is still generating.
     *
     * <p>Two jobs, and the second one is why the first live-target send failed. Keeping the counters
     * level stops the <em>next</em> Repeater send encrypting at an offset the server has left behind.
     * But once a session has diverged — which is precisely what a Repeater send does to it — the
     * client's ciphertext is no longer readable by the server at all, because the client is
     * encrypting at <i>T</i> while the server decrypts at <i>T + n</i>. Forwarding it unchanged hands
     * the Forms runtime noise, and it answers {@code FRM-93618} (architecture &sect;6.11).
     *
     * <p>So a diverged session's messages are decrypted on the leg facing the sender and re-encrypted
     * on the leg facing the receiver. That is the half of architecture &sect;6.2 that touches bytes,
     * and until now only the tests performed it.
     *
     * <p><strong>On the hot path budget.</strong> Architecture &sect;5 says key capture is the only
     * work done here, and this is a deliberate, bounded addition to it. Traffic that is not Forms
     * costs nothing. A Forms session that has never been sent into costs one map lookup — the two
     * legs agree, so there is nothing to translate. Only a session the user has already chosen to
     * inject into pays for two RC4 passes over the body, which for the 8-to-400-byte steady-state
     * messages in the capture is not measurable.
     *
     * @return the bytes to forward if they had to be re-encrypted, or null to send the message on
     *         unchanged
     */
    private byte[] trackForwarded(
            Object message, FormsDetector.FormsTarget forms, Direction direction, byte[] body) {

        if (streams == null || !forms.isEncrypted()) {
            return null;
        }
        // Only the real client's traffic moves both legs together. A hand-crafted resend of captured
        // ciphertext from Repeater or Intruder also reaches the server -- it is a valid Forms
        // message, it carries no draft markers, so it is forwarded unchanged -- but proxy history
        // never records it, so no later measurement can see the bytes the server consumed.
        //
        // Architecture §6.9 used to call that offset "not modelled". The first live-target send
        // showed what not-modelled meant in practice: guessed, silently (§6.11). It is now recorded
        // as unrecoverable, and Mode A refuses instead.
        if (!isFromProxy(message)) {
            noteUntrackedSend(forms, direction, body);
            return null;
        }
        Optional<SessionStreams> open = streams.forProxiedMessage(
                forms.sessionId(), keyStore.get(forms.sessionId()).orElse(null));
        if (open.isEmpty()) {
            return null;
        }

        SessionStreams.Forwarded forwarded =
                open.get().forward(direction, body, forms.pragma());
        if (!forwarded.rewritten()) {
            return null;
        }

        // The counters moved on both legs and the divergence is still there, so this has to reach
        // the project file: an extension reload between here and the next message would otherwise
        // resume from a position the session left behind. Only diverged sessions get here, which is
        // what keeps this from being a project-file write per proxied message.
        streams.checkpoint(open.get());
        return forwarded.body();
    }

    /**
     * Marks a session unrecoverable because ciphertext reached the server outside the proxy.
     *
     * <p>Two things deliberately do <em>not</em> desynchronise anything, and both would be easy to
     * get wrong:
     *
     * <ul>
     *   <li><b>Responses.</b> Only a request advances the server's request cipher, and the request
     *       that drew this response has already been marked. Marking again would be harmless but the
     *       reason recorded would name the wrong direction.
     *   <li><b>A {@code NULLPOST}.</b> The client writes those eight bytes straight to the socket
     *       without encrypting them, so they contribute nothing to any keystream (architecture
     *       &sect;1). Resending one moves no cipher and costs no session.
     * </ul>
     *
     * <p>Drafts never reach here at all: {@code RepeaterSendInterceptor} handles them and returns
     * before this method is called, which is exactly the distinction being drawn — a draft is
     * encrypted at send time and accounted for, a plain resend is not.
     */
    private void noteUntrackedSend(
            FormsDetector.FormsTarget forms, Direction direction, byte[] body) {

        if (direction != Direction.REQUEST || PragmaBody.isNullPost(body)) {
            return;
        }

        String reason = "Pragma " + forms.pragma() + " (" + body.length + " bytes of ciphertext) "
                + "was sent to the server from one of Burp's own tools without the Oracle Forms "
                + "draft markers, so it was forwarded unchanged and the server's request cipher "
                + "consumed it. Burp's proxy history has no record of that send.";

        if (streams.markDesynced(forms.sessionId(), reason)) {
            logging.logToError("Oracle Forms: session " + forms.sessionId() + " can no longer be "
                    + "appended to. " + reason + " Use \"Send decoded to Repeater\" rather than "
                    + "Burp's own Send to Repeater -- a draft is encrypted at send time and is "
                    + "accounted for. Restart the application for a fresh session.");
        }
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
