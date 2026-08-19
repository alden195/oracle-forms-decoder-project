package oracleforms.burp.proxy;

import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The single-use capability that lets a draft marker be trusted when it arrives from the Proxy.
 *
 * <h2>The problem this solves</h2>
 *
 * <p>Rule 1 of the marker contract (architecture &sect;6.5) honours {@code X-OracleForms-*} only on
 * requests from Repeater, Intruder and Extensions, and never from the Proxy — because a marker on
 * proxied traffic was put there by the client, and the client is the application under test (BApp
 * criterion 3). Mode D (&sect;6.12) needs a marked request that arrives <em>from the Proxy</em>,
 * which is exactly what that rule forbids.
 *
 * <p><strong>The rule is not relaxed.</strong> What is trusted is this token, not the origin. A
 * Proxy-originated marker without a valid one is still ignored and stripped, precisely as before.
 *
 * <h2>Why a forged marker would not be harmless</h2>
 *
 * <p>Worth stating, because "the client can already talk to its own server" makes it tempting to
 * treat this as a non-issue. A marker the client invented would have the handler treat the client's
 * own <em>ciphertext</em> as plaintext and encrypt it a second time — sending the server garbage —
 * while diverging the ledger by a length the client chose. That grants no new capability against the
 * server, but it corrupts the tester's view of the session and steers a crypto operation from
 * attacker-controlled input, which is the thing criterion 3 exists to prevent.
 *
 * <h2>Why it cannot be forged or replayed</h2>
 *
 * <ul>
 *   <li>128 bits from {@link SecureRandom}, so guessing is not a strategy.
 *   <li>Minted by the editor and stripped before the request leaves Burp, so the client never
 *       observes one.
 *   <li>Consumed on first use, so even a leaked one cannot be replayed.
 * </ul>
 *
 * <p>Bounded, because a user who converts a request and then drops it leaves a token nobody spends;
 * the oldest are evicted rather than accumulating. Losing an unspent token costs a refusal, which is
 * the safe direction.
 */
public final class InterceptTokens {

    /** Bytes of entropy per token. */
    private static final int TOKEN_BYTES = 16;

    /**
     * How many unspent tokens to keep.
     *
     * <p>One is live at a time in normal use — the request being held. The rest of the headroom is
     * for tokens abandoned by dropping a converted request, and it bounds what an enthusiastic user
     * can accumulate.
     */
    private static final int MAX_LIVE = 64;

    private final SecureRandom random = new SecureRandom();

    /** Access-ordered so eviction drops the least recently touched, not the least recently minted. */
    private final Map<String, Long> live = new LinkedHashMap<>(16, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Long> eldest) {
            return size() > MAX_LIVE;
        }
    };

    /** A fresh token, valid for exactly one send. */
    public String mint() {
        byte[] bytes = new byte[TOKEN_BYTES];
        random.nextBytes(bytes);
        String token = HexFormat.of().formatHex(bytes);
        synchronized (live) {
            live.put(token, System.currentTimeMillis());
        }
        return token;
    }

    /**
     * Spends a token, if it is one of ours.
     *
     * <p>Called from the proxy request thread, so it is a hash lookup and nothing else.
     *
     * @return true if the token was live and has now been consumed; false for anything else,
     *         including a token that has already been spent
     */
    public boolean consume(String token) {
        if (token == null || token.isBlank()) {
            return false;
        }
        synchronized (live) {
            return live.remove(token.trim()) != null;
        }
    }

    /** How many tokens are outstanding. For tests and diagnostics. */
    public int liveCount() {
        synchronized (live) {
            return live.size();
        }
    }

    /** Drops every outstanding token. Called on unload (BApp criterion 6). */
    public void clear() {
        synchronized (live) {
            live.clear();
        }
    }
}
