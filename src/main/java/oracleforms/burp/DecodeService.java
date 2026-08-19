package oracleforms.burp;

import burp.api.montoya.MontoyaApi;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import oracleforms.burp.history.PragmaHistorySource;
import oracleforms.codec.FhtParser;
import oracleforms.codec.model.FhtPacket;
import oracleforms.session.CheckpointCache;
import oracleforms.session.Direction;
import oracleforms.session.DictionaryScope;
import oracleforms.session.ReplayResult;
import oracleforms.session.SessionKey;
import oracleforms.session.SessionKeyStore;
import oracleforms.session.StreamReplayer;

/**
 * Turns a message into displayable text, off the EDT and off the proxy hot path.
 *
 * <p>Everything expensive in this extension happens here: the history scan, the RC4 replay, the
 * parse and the formatting. Editors call {@link #decode} and repaint when the future completes, so
 * nothing slow ever runs on the Swing thread (BApp criterion 5).
 *
 * <p>All caches are bounded LRUs holding plain arrays and strings, never Burp objects
 * (criterion 9), and {@link #shutdown()} releases the executor and every cache (criterion 6).
 */
public final class DecodeService implements DecodedBodyCache {

    /** Decoded text kept for recently viewed messages. */
    private static final int MAX_CACHED_RESULTS = 200;

    /** Session history indexes kept in memory. Each holds one session's bodies. */
    private static final int MAX_CACHED_SESSIONS = 3;

    /** Bodies decoded outside the replay path -- Repeater sends and their replies. */
    private static final int MAX_DIRECT_PLAINTEXTS = 64;

    /** What the editor displays. */
    public record DecodeResult(String text, boolean decoded) {
    }

    /**
     * The decrypted bytes of a message, or the reason there are none.
     *
     * <p>Separate from {@link DecodeResult} because the send path needs the bytes themselves, not a
     * rendering of them: a draft's body is FHT plaintext that the writer will edit and the
     * interceptor will re-encrypt.
     */
    public record Plaintext(byte[] bytes, String failure) {

        public boolean ok() {
            return bytes != null;
        }

        static Plaintext failed(String reason) {
            return new Plaintext(null, reason);
        }
    }

    private record ResultKey(String sessionId, Direction direction, int pragma) {
    }

    /**
     * Told when a message's decoded bytes are superseded after it was first rendered.
     *
     * <p>Exists for one case, and it is not cosmetic: the reply to a Repeater send is first decoded
     * at the ledger's offset and only afterwards, on the decode executor, at the offset
     * {@link oracleforms.session.ReplyOffsetRecovery} solves for. Without a way to say "that reading
     * has been replaced", the corrected one is computed and then never seen.
     */
    public interface DecodeUpdateListener {
        void decodeUpdated(String sessionId, Direction direction, int pragma);
    }

    private final MontoyaApi api;
    private final SessionKeyStore keyStore;
    private final CheckpointCache checkpoints;
    private final StreamReplayer replayer;
    private final FhtParser parser = new FhtParser();
    private final ExecutorService executor;

    private final Map<ResultKey, DecodeResult> results;
    private final Map<String, PragmaHistorySource> histories;
    private final Map<String, byte[]> directPlaintexts;

    /** Which rendered result each direct plaintext produced, so it can be dropped if superseded. */
    private final Map<String, ResultKey> directRenderedAs;

    /** Caveats to show beside a direct plaintext, for readings that are shown but not trusted. */
    private final Map<String, String> directNotes;

    /**
     * Open editors wanting to know about a superseded decode.
     *
     * <p>Weak: Burp creates an editor per view and never says when one is discarded, so a strong
     * registry would retain every tab the user has ever opened (criterion 9). Each pane keeps itself
     * alive by being the component Burp is holding.
     */
    private final Set<DecodeUpdateListener> listeners =
            Collections.newSetFromMap(new WeakHashMap<>());

    public DecodeService(MontoyaApi api, SessionKeyStore keyStore, DictionaryScope scope) {
        this.api = api;
        this.keyStore = keyStore;
        this.checkpoints = new CheckpointCache();
        this.replayer = new StreamReplayer(checkpoints, scope);

        ThreadFactory threads = new ThreadFactory() {
            private final AtomicInteger n = new AtomicInteger();

            @Override
            public Thread newThread(Runnable r) {
                // Daemon threads so a stuck decode can never keep the JVM alive; they are still
                // shut down explicitly on unload.
                Thread t = new Thread(r, "oracle-forms-decode-" + n.incrementAndGet());
                t.setDaemon(true);
                return t;
            }
        };
        this.executor = Executors.newFixedThreadPool(2, threads);

        this.results = boundedMap(MAX_CACHED_RESULTS);
        this.histories = boundedMap(MAX_CACHED_SESSIONS);
        this.directPlaintexts = boundedMap(MAX_DIRECT_PLAINTEXTS);
        this.directRenderedAs = boundedMap(MAX_DIRECT_PLAINTEXTS);
        this.directNotes = boundedMap(MAX_DIRECT_PLAINTEXTS);
    }

    /**
     * The decode executor, for work that must not run on a Burp thread.
     *
     * <p>Shared rather than given its own pool because it is the same kind of work under the same
     * lifetime: bounded, cancellable, and shut down with this service on unload (BApp criteria 5
     * and 6). A second pool would be a second thing to remember to stop.
     */
    public java.util.concurrent.Executor background() {
        return executor;
    }

    // ---- DecodedBodyCache -----------------------------------------------------------------

    @Override
    public void put(byte[] ciphertext, byte[] plaintext) {
        put(ciphertext, plaintext, null);
    }

    @Override
    public void put(byte[] ciphertext, byte[] plaintext, String note) {
        if (ciphertext == null || ciphertext.length == 0 || plaintext == null) {
            return;
        }
        String fingerprint = fingerprint(ciphertext);
        byte[] previous;
        synchronized (directPlaintexts) {
            previous = directPlaintexts.put(fingerprint, plaintext.clone());
        }
        synchronized (directNotes) {
            if (note == null || note.isBlank()) {
                directNotes.remove(fingerprint);
            } else {
                directNotes.put(fingerprint, note);
            }
        }
        if (previous != null && !Arrays.equals(previous, plaintext)) {
            supersede(fingerprint);
        }
    }

    /**
     * Registers an editor to be told when a decode it may be showing has been replaced.
     *
     * <p>The registry is weak, so registering does not keep the editor alive and there is nothing to
     * deregister — which matters because Burp never says when it has finished with one.
     */
    public void addUpdateListener(DecodeUpdateListener listener) {
        if (listener == null) {
            return;
        }
        synchronized (listeners) {
            listeners.add(listener);
        }
    }

    /**
     * Drops the rendering built from a superseded reading of a body, and tells open editors.
     *
     * <p>Both halves are necessary and they fix different things. Dropping the {@link #results}
     * entry matters because that cache is keyed by (session, direction, pragma) and never expires
     * within a project: left in place it would serve the stale rendering for the life of the
     * project, so not even closing and reopening the message would show the correction. The
     * notification matters because the pane the user is looking at right now has already painted,
     * and nothing else would ever ask it to paint again.
     */
    private void supersede(String fingerprint) {
        ResultKey key;
        synchronized (directRenderedAs) {
            key = directRenderedAs.get(fingerprint);
        }
        if (key == null) {
            // Nothing has rendered this body yet, so the new reading will be picked up on first
            // display and there is nothing to invalidate.
            return;
        }
        synchronized (results) {
            results.remove(key);
        }
        List<DecodeUpdateListener> current;
        synchronized (listeners) {
            current = List.copyOf(listeners);
        }
        for (DecodeUpdateListener listener : current) {
            try {
                listener.decodeUpdated(key.sessionId(), key.direction(), key.pragma());
            } catch (RuntimeException e) {
                api.logging().logToError("Oracle Forms: a decode listener failed: " + e);
            }
        }
    }

    @Override
    public Optional<byte[]> get(byte[] ciphertext) {
        if (ciphertext == null || ciphertext.length == 0) {
            return Optional.empty();
        }
        synchronized (directPlaintexts) {
            return Optional.ofNullable(directPlaintexts.get(fingerprint(ciphertext)))
                    .map(byte[]::clone);
        }
    }

    /**
     * A content hash of a body, used as the cache key.
     *
     * <p>SHA-256 rather than {@code Arrays.hashCode} because a collision here would show one
     * message's plaintext against another's bytes, which is a decoding lie rather than a cache miss.
     */
    private static String fingerprint(byte[] body) {
        try {
            byte[] digest = java.security.MessageDigest.getInstance("SHA-256").digest(body);
            return java.util.HexFormat.of().formatHex(digest, 0, 16);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required by every Java platform", e);
        }
    }

    private static <K, V> Map<K, V> boundedMap(int maxEntries) {
        return new LinkedHashMap<>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
                return size() > maxEntries;
            }
        };
    }

    /**
     * Decodes a message, returning immediately with a future.
     *
     * @param target    the identified session and pragma
     * @param direction which stream the body belongs to
     * @param rawBody   the body as captured, used for the cleartext and fallback views
     */
    public CompletableFuture<DecodeResult> decode(
            FormsDetector.FormsTarget target, Direction direction, byte[] rawBody) {

        ResultKey key = new ResultKey(target.sessionId(), direction, target.pragma());

        synchronized (results) {
            DecodeResult cached = results.get(key);
            if (cached != null) {
                return CompletableFuture.completedFuture(cached);
            }
        }

        try {
            return CompletableFuture.supplyAsync(() -> {
                DecodeResult result = decodeNow(target, direction, rawBody);
                synchronized (results) {
                    results.put(key, result);
                }
                return result;
            }, executor).exceptionally(throwable -> {
                api.logging().logToError("Oracle Forms: decode failed: " + throwable);
                return new DecodeResult(
                        "Decoding failed unexpectedly: " + throwable + "\n\n"
                                + FhtRenderer.hexDump(rawBody), false);
            });
        } catch (RejectedExecutionException e) {
            // The extension was unloaded while an editor tab was still open. supplyAsync throws
            // this *synchronously*, so exceptionally() above never sees it and it would otherwise
            // surface on the EDT. Reloading with tabs open is the normal development cycle, so this
            // path is common, not exotic.
            return CompletableFuture.completedFuture(new DecodeResult(
                    "The Oracle Forms extension has been unloaded, so this message cannot be "
                            + "decoded. Reload the extension and reopen this message.\n\n"
                            + FhtRenderer.hexDump(rawBody), false));
        }
    }

    /**
     * The decrypted bytes of a message, off the EDT.
     *
     * <p>Used when sending a decoded message to Repeater. Unlike {@link #decode}, this does not
     * render or cache anything — the caller wants the bytes.
     */
    public CompletableFuture<Plaintext> plaintextOf(
            FormsDetector.FormsTarget target, Direction direction, byte[] rawBody) {

        if (!target.isEncrypted()) {
            return CompletableFuture.completedFuture(new Plaintext(rawBody.clone(), null));
        }
        try {
            return CompletableFuture.supplyAsync(() -> {
                Optional<byte[]> direct = get(rawBody);
                if (direct.isPresent()) {
                    return new Plaintext(direct.get(), null);
                }
                Optional<SessionKey> key = keyStore.get(target.sessionId());
                ReplayResult replayed = replay(target, direction, key.orElse(null));
                if (replayed instanceof ReplayResult.MissingPragma) {
                    invalidateHistory(target.sessionId());
                    replayed = replay(target, direction, key.orElse(null));
                }
                if (replayed instanceof ReplayResult.Decrypted decrypted) {
                    return new Plaintext(decrypted.plaintext(), null);
                }
                if (replayed instanceof ReplayResult.NullPost) {
                    return new Plaintext(rawBody.clone(), null);
                }
                return Plaintext.failed(replayed.describe());
            }, executor).exceptionally(throwable -> {
                api.logging().logToError("Oracle Forms: plaintext extraction failed: " + throwable);
                return Plaintext.failed("Decoding failed unexpectedly: " + throwable);
            });
        } catch (RejectedExecutionException e) {
            return CompletableFuture.completedFuture(
                    Plaintext.failed("The Oracle Forms extension has been unloaded."));
        }
    }

    private DecodeResult decodeNow(
            FormsDetector.FormsTarget target, Direction direction, byte[] rawBody) {

        String label = "Oracle Forms - session " + target.sessionId()
                + " - pragma " + target.pragma() + " - " + direction.name().toLowerCase();

        if (!target.isEncrypted()) {
            return new DecodeResult(FhtRenderer.renderCleartext(rawBody, label + " (cleartext)"), true);
        }

        // A body decoded outside the replay path -- a Repeater reply -- is already plaintext here,
        // and history has no record of it to replay from.
        Optional<byte[]> direct = get(rawBody);
        if (direct.isPresent()) {
            // Remember which result this body produced, so a later, better reading of the same
            // bytes can invalidate it rather than being computed into a cache nobody reads again.
            String fingerprint = fingerprint(rawBody);
            synchronized (directRenderedAs) {
                directRenderedAs.put(fingerprint,
                        new ResultKey(target.sessionId(), direction, target.pragma()));
            }
            String note;
            synchronized (directNotes) {
                note = directNotes.get(fingerprint);
            }
            String heading = label + " (sent from Burp"
                    + (note == null || note.isBlank() ? "" : "; " + note) + ")";
            FhtPacket packet = parser.parse(direct.get(), new oracleforms.codec.StringDictionary());
            return new DecodeResult(
                    FhtRenderer.render(packet, heading, direct.get(),
                            new ReplayResult.FragmentGroup(
                                    target.pragma(), target.pragma(), target.pragma(), true)),
                    packet.outcome().isComplete());
        }

        Optional<SessionKey> key = keyStore.get(target.sessionId());
        ReplayResult replayed = replay(target, direction, key.orElse(null));

        // A gap can simply mean the index predates traffic that has since been proxied. Rebuild it
        // once and retry before reporting the message as undecodable.
        if (replayed instanceof ReplayResult.MissingPragma) {
            invalidateHistory(target.sessionId());
            replayed = replay(target, direction, key.orElse(null));
        }

        // A NULLPOST is a successful, complete reading of the message — there is simply no payload.
        // Reporting it as a decode failure would be wrong and would bury the real failures.
        if (replayed instanceof ReplayResult.NullPost nullPost) {
            return new DecodeResult(
                    FhtRenderer.renderNullPost(rawBody, label, nullPost.describe()), true);
        }

        if (replayed instanceof ReplayResult.Decrypted decrypted) {
            FhtPacket packet = parser.parse(decrypted.plaintext(), decrypted.dictionary());
            return new DecodeResult(
                    FhtRenderer.render(packet, label, decrypted.plaintext(), decrypted.fragments()),
                    packet.outcome().isComplete() && decrypted.fragments().complete());
        }

        // Every failure states its reason and still shows the bytes, so a message is never a blank
        // tab (architecture §5).
        String text = label + "\n"
                + "-".repeat(Math.min(label.length(), 100)) + "\n\n"
                + "Could not decode this message.\n\n"
                + replayed.describe() + "\n\n"
                + "Raw (still encrypted) body:\n"
                + FhtRenderer.hexDump(rawBody);
        return new DecodeResult(text, false);
    }

    private ReplayResult replay(
            FormsDetector.FormsTarget target, Direction direction, SessionKey key) {
        return replayer.replay(
                target.sessionId(), key, direction, target.pragma(), historyFor(target.sessionId()));
    }

    /**
     * The session's history index, built on first use and cached.
     *
     * <p>Public because the send path needs the same index this one does: measuring a session's tail
     * walks exactly the bodies a decode walks, and building a second copy would double both the scan
     * and the memory.
     */
    public PragmaHistorySource historyFor(String sessionId) {
        synchronized (histories) {
            PragmaHistorySource cached = histories.get(sessionId);
            if (cached != null) {
                return cached;
            }
        }
        // Built outside the lock: this walks proxy history and can take a moment.
        PragmaHistorySource built = PragmaHistorySource.forSession(api, sessionId);
        synchronized (histories) {
            histories.put(sessionId, built);
        }
        return built;
    }

    /** Drops a session's cached history index, so the next decode rescans. */
    public void invalidateHistory(String sessionId) {
        synchronized (histories) {
            histories.remove(sessionId);
        }
        synchronized (results) {
            results.keySet().removeIf(k -> k.sessionId().equals(sessionId));
        }
    }

    /** Drops everything cached for a session, including its replay checkpoints. */
    public void invalidateSession(String sessionId) {
        invalidateHistory(sessionId);
        checkpoints.invalidate(sessionId);
    }

    /** Releases the executor and all caches. Called on extension unload (BApp criterion 6). */
    public void shutdown() {
        executor.shutdownNow();
        try {
            if (!executor.awaitTermination(2, TimeUnit.SECONDS)) {
                api.logging().logToError(
                        "Oracle Forms: decode executor did not stop within 2 seconds");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        synchronized (results) {
            results.clear();
        }
        synchronized (histories) {
            histories.clear();
        }
        synchronized (directPlaintexts) {
            directPlaintexts.clear();
        }
        synchronized (directRenderedAs) {
            directRenderedAs.clear();
        }
        synchronized (directNotes) {
            directNotes.clear();
        }
        synchronized (listeners) {
            listeners.clear();
        }
        checkpoints.clear();
    }
}
