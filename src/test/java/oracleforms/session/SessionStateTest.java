package oracleforms.session;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import oracleforms.codec.Rc4Stream;
import oracleforms.codec.StringDictionary;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Covers the key record, the in-memory store, and the checkpoint cache's bounds. */
class SessionStateTest {

    private static SessionKey key(String id, long lastSeen) {
        return new SessionKey(id, new byte[] {1, 2, 3, 4, 5}, "host", 0L, lastSeen, "",
                KeySource.DERIVED);
    }

    @Test
    @DisplayName("key hex round-trips, tolerating the formats a user might paste")
    void keyHexParsing() {
        byte[] expected = {0x33, (byte) 0xCD, (byte) 0xAE, 0x22, (byte) 0xBC};

        assertEquals("33cdae22bc",
                new SessionKey("s", expected, "h", 0, 0, "", KeySource.MANUAL).keyHex());

        assertArrayEquals(expected, SessionKey.parseKeyHex("33cdae22bc"));
        assertArrayEquals(expected, SessionKey.parseKeyHex("33CDAE22BC"));
        assertArrayEquals(expected, SessionKey.parseKeyHex("0x33cdae22bc"));
        assertArrayEquals(expected, SessionKey.parseKeyHex("33:cd:ae:22:bc"));
        assertArrayEquals(expected, SessionKey.parseKeyHex(" 33 cd ae 22 bc "));
    }

    @Test
    @DisplayName("rejects a key of the wrong length rather than padding it")
    void rejectsBadKeys() {
        assertThrows(IllegalArgumentException.class, () -> SessionKey.parseKeyHex("33cdae22"));
        assertThrows(IllegalArgumentException.class, () -> SessionKey.parseKeyHex("33cdae22bcdd"));
        assertThrows(IllegalArgumentException.class, () -> SessionKey.parseKeyHex("zzzzzzzzzz"));
        assertThrows(IllegalArgumentException.class, () -> SessionKey.parseKeyHex(null));
        assertThrows(IllegalArgumentException.class,
                () -> new SessionKey("s", new byte[4], "h", 0, 0, "", KeySource.DERIVED));
        assertThrows(IllegalArgumentException.class,
                () -> new SessionKey("", new byte[5], "h", 0, 0, "", KeySource.DERIVED));
    }

    @Test
    @DisplayName("the key record copies its bytes in and out")
    void keyBytesAreDefensivelyCopied() {
        byte[] source = {1, 2, 3, 4, 5};
        SessionKey sessionKey = new SessionKey("s", source, "h", 0, 0, "", KeySource.DERIVED);

        source[0] = 99;
        assertEquals(1, sessionKey.key()[0], "mutating the source must not change the stored key");

        sessionKey.key()[0] = 99;
        assertEquals(1, sessionKey.key()[0], "mutating the returned array must not change it either");
    }

    @Test
    @DisplayName("equality compares key contents, not array identity")
    void keyEquality() {
        assertEquals(key("s", 5), key("s", 5));
        assertEquals(key("s", 5).hashCode(), key("s", 5).hashCode());
        assertFalse(key("s", 5).equals(key("s", 6)));
    }

    @Test
    @DisplayName("the store lists most recently seen first")
    void storeOrdersByLastSeen() {
        SessionKeyStore store = new InMemorySessionKeyStore();
        store.put(key("old", 100));
        store.put(key("newest", 300));
        store.put(key("middle", 200));

        assertEquals(java.util.List.of("newest", "middle", "old"),
                store.list().stream().map(SessionKey::sessionId).toList());
    }

    @Test
    @DisplayName("forget and clear actually remove keys")
    void storeForgetAndClear() {
        SessionKeyStore store = new InMemorySessionKeyStore();
        store.put(key("a", 1));
        store.put(key("b", 2));

        assertTrue(store.forget("a"));
        assertFalse(store.forget("a"));
        assertFalse(store.contains("a"));
        assertEquals(1, store.size());

        store.clear();
        assertEquals(0, store.size());
        assertTrue(store.get("b").isEmpty());
    }

    @Test
    @DisplayName("checkpoints snapshot state rather than aliasing it")
    void checkpointIsASnapshot() {
        Rc4Stream stream = new Rc4Stream(new byte[] {1, 2, 3, 4, 5});
        StringDictionary dictionary = new StringDictionary();
        dictionary.put(1, "before");

        Checkpoint checkpoint = Checkpoint.after(10, stream, dictionary);

        stream.skip(500);
        dictionary.put(1, "after");

        assertEquals("before", checkpoint.dictionary().get(1));
        assertArrayEquals(
                new Rc4Stream(new byte[] {1, 2, 3, 4, 5}).applied(new byte[4]),
                checkpoint.rc4().applied(new byte[4]),
                "the checkpoint must hold the position it was taken at");
    }

    @Test
    @DisplayName("the checkpoint cache stays bounded and keeps a usable spread")
    void checkpointCacheIsBounded() {
        CheckpointCache cache = new CheckpointCache(2, 8);
        Rc4Stream stream = new Rc4Stream(new byte[] {1, 2, 3, 4, 5});
        StringDictionary dictionary = new StringDictionary();

        for (int pragma = 3; pragma <= 200; pragma++) {
            cache.put("session", Direction.REQUEST, Checkpoint.after(pragma, stream, dictionary));
        }

        assertTrue(cache.checkpointCount() <= 8,
                "cache grew to " + cache.checkpointCount() + " entries");

        // Thinning must keep the newest, which is where the user is reading.
        assertEquals(200, cache.nearestAtOrBefore("session", Direction.REQUEST, 200)
                .orElseThrow().pragma());
        // ...and must still offer a resume point near the start.
        assertTrue(cache.nearestAtOrBefore("session", Direction.REQUEST, 50).isPresent());
    }

    @Test
    @DisplayName("the cache bounds the number of streams it tracks")
    void checkpointCacheBoundsStreams() {
        CheckpointCache cache = new CheckpointCache(2, 8);
        Rc4Stream stream = new Rc4Stream(new byte[] {1, 2, 3, 4, 5});
        StringDictionary dictionary = new StringDictionary();

        for (int i = 0; i < 10; i++) {
            cache.put("session-" + i, Direction.REQUEST, Checkpoint.after(3, stream, dictionary));
        }

        assertTrue(cache.nearestAtOrBefore("session-0", Direction.REQUEST, 3).isEmpty(),
                "the oldest stream should have been evicted");
        assertTrue(cache.nearestAtOrBefore("session-9", Direction.REQUEST, 3).isPresent());
    }

    @Test
    @DisplayName("invalidate drops a session's cached state in both directions")
    void invalidateClearsSession() {
        CheckpointCache cache = new CheckpointCache();
        Rc4Stream stream = new Rc4Stream(new byte[] {1, 2, 3, 4, 5});
        StringDictionary dictionary = new StringDictionary();

        cache.put("s", Direction.REQUEST, Checkpoint.after(3, stream, dictionary));
        cache.put("s", Direction.RESPONSE, Checkpoint.after(3, stream, dictionary));

        cache.invalidate("s");

        assertTrue(cache.nearestAtOrBefore("s", Direction.REQUEST, 3).isEmpty());
        assertTrue(cache.nearestAtOrBefore("s", Direction.RESPONSE, 3).isEmpty());
    }
}
