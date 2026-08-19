package oracleforms.burp.proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The capability that lets Mode D accept a marker from the Proxy without weakening
 * {@code DraftMarkers}' trust rule (architecture &sect;6.12).
 *
 * <p>Worth testing directly because it is a security property rather than a convenience: if a token
 * could be guessed, replayed, or spent twice, then a marker set the application under test invented
 * would be honoured — and the handler would encrypt the client's own ciphertext a second time while
 * diverging the ledger by a length the client chose.
 */
class InterceptTokensTest {

    private final InterceptTokens tokens = new InterceptTokens();

    @Test
    @DisplayName("a minted token is accepted exactly once")
    void aTokenIsSingleUse() {
        String token = tokens.mint();

        assertTrue(tokens.consume(token), "the first use must be honoured");
        assertFalse(tokens.consume(token),
                "the second must not: a leaked token cannot be worth replaying");
    }

    @Test
    @DisplayName("anything not minted here is refused")
    void unmintedTokensAreRefused() {
        tokens.mint();

        assertFalse(tokens.consume(null));
        assertFalse(tokens.consume(""));
        assertFalse(tokens.consume("   "));
        assertFalse(tokens.consume("00000000000000000000000000000000"));
        assertFalse(tokens.consume("not-a-token"));
    }

    @Test
    @DisplayName("tokens are unique and carry real entropy")
    void tokensAreUnique() {
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < 500; i++) {
            String token = tokens.mint();
            assertTrue(seen.add(token), "minted a duplicate token");
            assertEquals(32, token.length(), "128 bits, hex encoded");
            assertTrue(token.matches("[0-9a-f]{32}"));
        }
        // Guessing is not a strategy, but neither is a fixed prefix.
        assertNotEquals(1, seen.stream().map(t -> t.substring(0, 8)).distinct().count());
    }

    @Test
    @DisplayName("surrounding whitespace from a header value is tolerated")
    void headerWhitespaceIsTolerated() {
        String token = tokens.mint();
        assertTrue(tokens.consume("  " + token + "  "));
    }

    @Test
    @DisplayName("outstanding tokens are bounded, and eviction refuses rather than admits")
    void outstandingTokensAreBounded() {
        String first = tokens.mint();
        for (int i = 0; i < 200; i++) {
            tokens.mint();
        }

        assertTrue(tokens.liveCount() <= 64, "unspent tokens must not accumulate without bound");
        assertFalse(tokens.consume(first),
                "an evicted token must fail closed — a refused edit, never an accepted one");
    }

    @Test
    @DisplayName("clearing on unload leaves nothing spendable")
    void clearingRevokesEverything() {
        String token = tokens.mint();
        tokens.clear();

        assertEquals(0, tokens.liveCount());
        assertFalse(tokens.consume(token));
    }
}
