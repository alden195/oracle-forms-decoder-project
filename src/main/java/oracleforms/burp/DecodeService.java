package oracleforms.burp;

import burp.api.montoya.MontoyaApi;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
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
public final class DecodeService {

    /** Decoded text kept for recently viewed messages. */
    private static final int MAX_CACHED_RESULTS = 200;

    /** Session history indexes kept in memory. Each holds one session's bodies. */
    private static final int MAX_CACHED_SESSIONS = 3;

    /** What the editor displays. */
    public record DecodeResult(String text, boolean decoded) {
    }

    private record ResultKey(String sessionId, Direction direction, int pragma) {
    }

    private final MontoyaApi api;
    private final SessionKeyStore keyStore;
    private final CheckpointCache checkpoints;
    private final StreamReplayer replayer;
    private final FhtParser parser = new FhtParser();
    private final ExecutorService executor;

    private final Map<ResultKey, DecodeResult> results;
    private final Map<String, PragmaHistorySource> histories;

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

    private DecodeResult decodeNow(
            FormsDetector.FormsTarget target, Direction direction, byte[] rawBody) {

        String label = "Oracle Forms - session " + target.sessionId()
                + " - pragma " + target.pragma() + " - " + direction.name().toLowerCase();

        if (!target.isEncrypted()) {
            return new DecodeResult(FhtRenderer.renderCleartext(rawBody, label + " (cleartext)"), true);
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

    /** The session's history index, built on first use and cached. */
    private PragmaHistorySource historyFor(String sessionId) {
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
        checkpoints.clear();
    }
}
