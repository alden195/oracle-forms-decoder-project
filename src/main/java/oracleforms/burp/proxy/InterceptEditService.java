package oracleforms.burp.proxy;

import burp.api.montoya.logging.Logging;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import java.util.function.Function;
import oracleforms.burp.FormsDetector;
import oracleforms.session.Direction;
import oracleforms.session.KeyValidation;
import oracleforms.session.PragmaBody;
import oracleforms.session.PragmaSource;
import oracleforms.session.SessionKey;
import oracleforms.session.SessionKeyStore;
import oracleforms.session.SessionStreams;
import oracleforms.session.SessionTail;
import oracleforms.session.StreamGapException;
import oracleforms.session.StreamLeg;
import oracleforms.session.StreamPositionUnknownException;
import oracleforms.session.StreamRegistry;
import oracleforms.session.StreamReplayer;

/**
 * Decides whether a request the proxy is holding can be edited, and decodes it if so.
 *
 * <p>The preparation half of Mode D (architecture &sect;6.12); {@code FormsHttpHandler} owns the
 * other half, at Forward. Everything here runs on the decode executor, because opening a session's
 * ledger walks its proxy history and may run the cipher over every byte of it — with the client
 * blocked on the very request being examined, that is not work for the EDT.
 *
 * <h2>Displaying must not move the ledger</h2>
 *
 * <p>The decode uses {@link SessionStreams#cipherAt}, a <em>detached</em> copy at the leg's current
 * position. Burp calls {@code setRequestResponse} whenever a tab is shown, not only when the user
 * intends to edit, so a decode that advanced the ledger would move it twice for a second look at the
 * same message and would move it at all for a message the user goes on to drop. Only Forward
 * commits.
 *
 * <h2>The offset checks itself</h2>
 *
 * <p>This is the strongest guarantee in the whole of &sect;6, and no other send mode can obtain it.
 * We decrypt at the offset we believe; if that offset is right the plaintext is well-formed FHT with
 * property ids drawn from the table, and if it is wrong it is uniform noise. So the wrong-offset
 * failure class — the one that produced {@code FRM-93618} and cost a live session — becomes
 * something this refuses <em>before</em> the user is offered a cell to type in, rather than something
 * the server discovers after the bytes have gone.
 *
 * <p>Its limit is honest and reported rather than hidden: steady-state Forms requests are 8 to 12
 * bytes and often carry no properties at all, and there is no structure in that to be right or wrong
 * about. Such a message is marked {@link Verdict#UNVERIFIABLE} and editing is still offered, because
 * refusing every small request would refuse most of the protocol — but the banner says so.
 */
public final class InterceptEditService {

    /**
     * Below this a decoded body carries too little structure to judge.
     *
     * <p>The same bar {@code RepeaterSendInterceptor.readsAsFht} applies to a reply, deliberately:
     * the two are asking the same question about the same kind of evidence, and having them disagree
     * once already produced a system that called a reading too weak to display and strong enough to
     * condemn the alternative.
     */
    private static final int MIN_JUDGEABLE = 24;


    /** What the FHT check made of the decoded bytes. */
    public enum Verdict {
        /** Enough structure to judge, and it reads as FHT. The offset is almost certainly right. */
        VERIFIED,
        /** Too little structure to judge either way. Editing is offered, and labelled. */
        UNVERIFIABLE,
        /** Enough structure to judge, and it is not FHT. The ledger is wrong; editing is refused. */
        FAILED
    }

    /**
     * The outcome of preparing an intercepted request for editing.
     *
     * @param plaintext            the decoded body, or null when this cannot be edited
     * @param token                the single-use capability the send will be authorised by
     * @param originalStreamLength what the client's own body contributed to its request keystream
     * @param verdict              what the FHT check concluded
     * @param detail               a sentence for the banner, whether it succeeded or not
     */
    public record Prepared(
            byte[] plaintext,
            String token,
            int originalStreamLength,
            long position,
            Verdict verdict,
            String detail) {

        public boolean ok() {
            return plaintext != null;
        }

        static Prepared refused(Verdict verdict, String detail) {
            return new Prepared(null, null, 0, -1, verdict, detail);
        }
    }

    private final SessionKeyStore keyStore;
    private final StreamRegistry registry;
    private final Function<String, PragmaSource> historyForSession;
    private final java.util.function.Consumer<String> refreshHistory;
    private final InterceptTokens tokens;
    private final Executor background;
    private final Logging logging;

    public InterceptEditService(
            SessionKeyStore keyStore,
            StreamRegistry registry,
            Function<String, PragmaSource> historyForSession,
            java.util.function.Consumer<String> refreshHistory,
            InterceptTokens tokens,
            Executor background,
            Logging logging) {

        this.keyStore = keyStore;
        this.registry = registry;
        this.historyForSession = historyForSession;
        this.refreshHistory = refreshHistory;
        this.tokens = tokens;
        this.background = background;
        this.logging = logging;
    }

    /**
     * The session's ledger, opened or resumed.
     *
     * <p>Exposed so the handler can reach it at Forward without taking a second copy of the history
     * function and the registry. Normally a cache hit, because {@link #prepare} opened it at display
     * time — it is repeated because an extension reload or an LRU eviction between the two is
     * possible, and encrypting without a ledger is not.
     *
     * <p>Call it off the EDT: on a miss it walks the session's captured traffic.
     */
    public SessionStreams openLedger(String sessionId, SessionKey key, int pragma)
            throws StreamPositionUnknownException {
        return registry.openBefore(
                sessionId, key, historyFor(sessionId, pragma), pragma);
    }

    /** Spends the capability that authorises one in-flight edit. */
    public boolean consumeToken(String token) {
        return tokens.consume(token);
    }

    /** Releases every unspent capability. Called on unload (BApp criterion 6). */
    public void shutdown() {
        tokens.clear();
    }

    /**
     * Works out whether this held request can be edited, and decodes it if it can.
     *
     * <p>Never throws and never blocks the caller: the answer, including every refusal, arrives as a
     * completed {@link Prepared}.
     */
    public CompletableFuture<Prepared> prepare(
            FormsDetector.FormsTarget target, byte[] ciphertext) {

        if (target == null || ciphertext == null) {
            return CompletableFuture.completedFuture(
                    Prepared.refused(Verdict.FAILED, "there is no message here to edit."));
        }
        if (!target.isEncrypted()) {
            return CompletableFuture.completedFuture(Prepared.refused(Verdict.FAILED,
                    "pragma " + target.pragma() + " is cleartext, so there is nothing to decode "
                            + "and Burp's own Raw tab already edits it."));
        }
        if (PragmaBody.isNullPost(ciphertext)) {
            return CompletableFuture.completedFuture(Prepared.refused(Verdict.FAILED,
                    "this is a NULLPOST: the client sent no payload, it is polling for the rest of "
                            + "a response. There is nothing in it to edit."));
        }

        try {
            return CompletableFuture.supplyAsync(() -> prepareNow(target, ciphertext), background)
                    .exceptionally(throwable -> {
                        logging.logToError("Oracle Forms: could not prepare an intercepted request "
                                + "for editing: " + throwable);
                        return Prepared.refused(Verdict.FAILED,
                                "preparing this request for editing failed unexpectedly: "
                                        + throwable);
                    });
        } catch (RejectedExecutionException e) {
            return CompletableFuture.completedFuture(Prepared.refused(Verdict.FAILED,
                    "the Oracle Forms extension has been unloaded."));
        }
    }

    private Prepared prepareNow(FormsDetector.FormsTarget target, byte[] ciphertext) {
        Optional<SessionKey> key = keyStore.get(target.sessionId());
        if (key.isEmpty()) {
            return Prepared.refused(Verdict.FAILED,
                    "no key is stored for session " + target.sessionId() + ", so this message "
                            + "cannot be decoded. Recover it from the Sessions tab - run a "
                            + "retroactive history scan, or enter it by hand.");
        }

        PragmaSource history = historyFor(target.sessionId(), target.pragma());

        SessionStreams streams;
        try {
            // Positioned *before* this message, not at the session's tail. Burp records a request in
            // proxy history the moment it intercepts it, so the tail includes the very message being
            // held -- bytes the server has not read (architecture §6.12).
            streams = registry.openBefore(
                    target.sessionId(), key.get(), history, target.pragma());
        } catch (StreamPositionUnknownException e) {
            // A gap or a desync. Either way this session's keystream position is not known, and
            // encrypting at a guessed one is what the whole send path exists not to do.
            return Prepared.refused(Verdict.FAILED, e.getMessage());
        }

        // Detached, at the client leg's current position. The ledger must be exactly where it was
        // when this returns -- see the class comment.
        long position = streams.consumed(StreamLeg.CLIENT_REQUEST);
        byte[] plaintext = streams.cipherAt(StreamLeg.CLIENT_REQUEST).applied(ciphertext);

        KeyValidation.Signals signals = KeyValidation.signalsOf(plaintext);
        Verdict verdict = judge(plaintext, signals);

        if (verdict == Verdict.VERIFIED) {
            return offered(plaintext, ciphertext, position, verdict, signals, "");
        }

        // The ledger did not prove itself, so ask the traffic. A ledger is an accumulation -- one
        // measurement plus every message since -- and the only way to check an accumulation is
        // against something measured independently.
        //
        // Skipped for a diverged session: history has no record of what this extension injected, so
        // a measurement of it would be wrong by exactly the amount that matters. Its counters are
        // persisted for precisely that reason.
        if (!streams.diverged()) {
            Optional<Prepared> reconciled =
                    reconcile(target, ciphertext, key.get(), history, position, verdict, signals);
            if (reconciled.isPresent()) {
                return reconciled.get();
            }
        }

        if (verdict == Verdict.FAILED) {
            return Prepared.refused(verdict,
                    "this message does not decode as Oracle Forms data at the keystream offset this "
                            + "session is believed to be at, " + position + " (" + signals.describe()
                            + "). That means the offset is wrong, so an edit encrypted at it would "
                            + "reach the server as noise and could end the session. Editing is "
                            + "refused; the request can still be forwarded unchanged.");
        }
        return offered(plaintext, ciphertext, position, verdict, signals, "");
    }

    /**
     * Checks the ledger against the position this session's captured traffic implies, and corrects
     * it if the traffic is right.
     *
     * <p>This is {@code ReplyOffsetRecovery}'s rule applied to the request leg: a candidate offset is
     * <em>verified before it is believed</em>. There is no search here because there is nothing to
     * search — the two candidates are the ledger and the measurement, and the message in hand decides
     * between them.
     *
     * <p>The disagreement this exists for was real: a tail measured while a request sat in the
     * Intercept tab counted that request, and every later position in the session inherited the
     * error, silently, because forwarding the held message then advanced the ledger over the same
     * bytes a second time.
     *
     * @return the answer when the disagreement settles the matter, or empty to leave the decision to
     *         the caller
     */
    private Optional<Prepared> reconcile(
            FormsDetector.FormsTarget target,
            byte[] ciphertext,
            SessionKey key,
            PragmaSource history,
            long ledgerPosition,
            Verdict ledgerVerdict,
            KeyValidation.Signals ledgerSignals) {

        long candidate;
        try {
            // The sum first, and the ciphers only if it disagrees: measuring is a walk over a map,
            // whereas building a ledger runs RC4 over every byte the session has consumed.
            candidate = SessionTail.before(history, target.pragma()).requestBytes();
        } catch (StreamGapException e) {
            // No second opinion available. The gap may well predate the ledger, which has been
            // tracking live traffic since, so this is not itself evidence against it.
            return Optional.empty();
        }
        if (candidate == ledgerPosition) {
            return Optional.empty();
        }

        SessionStreams measured;
        try {
            measured = registry.measureBefore(
                    target.sessionId(), key, history, target.pragma());
        } catch (StreamGapException e) {
            return Optional.empty();
        }

        byte[] plaintext = measured.cipherAt(StreamLeg.CLIENT_REQUEST).applied(ciphertext);
        KeyValidation.Signals signals = KeyValidation.signalsOf(plaintext);

        if (judge(plaintext, signals) == Verdict.VERIFIED) {
            if (!registry.resynchronise(measured)) {
                return Optional.of(Prepared.refused(Verdict.FAILED,
                        "this message decodes correctly at keystream offset " + candidate
                                + ", not at " + ledgerPosition + " where this session's ledger is, "
                                + "but the ledger cannot be corrected: the session has diverged, and "
                                + "its counters are the only record of traffic proxy history never "
                                + "saw. Editing is refused."));
            }
            logging.logToOutput("Oracle Forms: session " + target.sessionId()
                    + " was at keystream offset " + ledgerPosition + " for pragma "
                    + target.pragma() + ", but the message decodes as FHT at " + candidate
                    + " (" + signals.describe() + "), which its captured traffic agrees with. The "
                    + "ledger has been resynchronised to " + candidate + ".");
            return Optional.of(offered(plaintext, ciphertext, candidate, Verdict.VERIFIED, signals,
                    " This session's recorded position was " + ledgerPosition
                            + ", which does not decode; it has been corrected to the position its "
                            + "captured traffic implies."));
        }

        // The two disagree and the message cannot tell them apart. Refusing is the only honest
        // answer: an offset nothing can check is exactly what the send path exists not to use, and
        // an edit encrypted at the wrong one reaches the Forms runtime as noise.
        return Optional.of(Prepared.refused(Verdict.FAILED,
                "this session's keystream position is in doubt. Its ledger says " + ledgerPosition
                        + " (" + ledgerSignals.describe() + ") and the traffic captured before "
                        + "pragma " + target.pragma() + " says " + candidate + " ("
                        + signals.describe() + ")"
                        + (ledgerVerdict == Verdict.UNVERIFIABLE
                                ? ", and this message is too small to tell which is right"
                                : ", and the message decodes as Oracle Forms data at neither")
                        + ". Editing is refused; the request can still be forwarded unchanged. A "
                        + "larger message from this session will settle it and repair the ledger."));
    }

    /** A decode the user may edit, with the banner that goes with it. */
    private Prepared offered(
            byte[] plaintext,
            byte[] ciphertext,
            long position,
            Verdict verdict,
            KeyValidation.Signals signals,
            String correction) {

        String detail = verdict == Verdict.VERIFIED
                ? "Decoded and verified at keystream offset "
                        + position + " (" + signals.describe()
                        + "), so the offset this will be re-encrypted at is confirmed." + correction
                : "Decoded at keystream offset " + position
                        + ", but this message is too small to confirm the offset from ("
                        + signals.describe() + "). Editing is offered anyway, because most "
                        + "steady-state Forms requests are this size." + correction;

        return new Prepared(
                plaintext, tokens.mint(), ciphertext.length, position, verdict, detail);
    }

    /**
     * The session's captured traffic, rebuilt first if the index predates what we need from it.
     *
     * <p>The index is cached per session, and on a live session it goes stale as the client talks.
     * Measuring from a stale one silently reports a short position — {@link
     * oracleforms.session.SessionTail} stops at the first absence — so the index has to be known to
     * reach the message before the one being held. That is the exact test, and it costs one lookup:
     * an index containing pragma {@code pragma - 1} was built after it was captured, and pragma
     * numbering is contiguous, so it contains everything earlier too.
     */
    private PragmaSource historyFor(String sessionId, int pragma) {
        PragmaSource history = historyForSession.apply(sessionId);
        if (refreshHistory == null || pragma <= StreamReplayer.FIRST_ENCRYPTED_PRAGMA
                || history.body(Direction.REQUEST, pragma - 1).isPresent()) {
            return history;
        }
        refreshHistory.accept(sessionId);
        return historyForSession.apply(sessionId);
    }

    /**
     * Whether the decoded bytes read as FHT.
     *
     * <p>A body with no properties is not evidence of failure — the capture is full of short
     * structural messages — so it is unverifiable rather than wrong. Only a body large enough to
     * judge, that produced properties, and that {@link KeyValidation#readsAsFht} will not vouch for,
     * is a decode this refuses to build on.
     */
    private static Verdict judge(byte[] plaintext, KeyValidation.Signals signals) {
        if (plaintext.length < MIN_JUDGEABLE || signals.properties() == 0) {
            return Verdict.UNVERIFIABLE;
        }
        return KeyValidation.readsAsFht(signals) ? Verdict.VERIFIED : Verdict.FAILED;
    }
}
