package oracleforms.session;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class KeyStoreJsonTest {

    private static SessionKey key(String id, String label) {
        return new SessionKey(id, new byte[] {0x33, (byte) 0xCD, (byte) 0xAE, 0x22, (byte) 0xBC},
                "forms.example.edu", 1000L, 2000L, label, KeySource.DERIVED);
    }

    @Test
    @DisplayName("round-trips a store through export and import")
    void roundTrip() {
        List<SessionKey> original = List.of(
                key("session-one!-1111111111", "login flow"),
                key("session-two!-2222222222", ""));

        List<String> problems = new ArrayList<>();
        List<SessionKey> imported = KeyStoreJson.importFrom(KeyStoreJson.export(original), problems);

        assertTrue(problems.isEmpty(), problems.toString());
        assertEquals(original, imported);
    }

    @Test
    @DisplayName("survives values containing quotes, backslashes and newlines")
    void escapesAwkwardValues() {
        SessionKey awkward = new SessionKey("id", new byte[] {1, 2, 3, 4, 5}, "host",
                1L, 2L, "he said \"hi\"\nand C:\\path\ttab", KeySource.MANUAL);

        List<SessionKey> imported =
                KeyStoreJson.importFrom(KeyStoreJson.export(List.of(awkward)), null);

        assertEquals(1, imported.size());
        assertEquals("he said \"hi\"\nand C:\\path\ttab", imported.get(0).label());
        assertEquals(KeySource.MANUAL, imported.get(0).source());
    }

    @Test
    @DisplayName("an empty store round-trips to an empty store")
    void emptyStore() {
        assertTrue(KeyStoreJson.importFrom(KeyStoreJson.export(List.of()), null).isEmpty());
    }

    /** Import files are user-supplied, so a bad entry must be dropped and reported, not fatal. */
    @Test
    @DisplayName("skips malformed entries and says which")
    void skipsMalformedEntries() {
        String json = """
                [
                  { "sessionId": "good", "key": "33cdae22bc", "host": "h",
                    "firstSeen": 1, "lastSeen": 2, "label": "", "source": "derived" },
                  { "sessionId": "short-key", "key": "33cd" },
                  { "key": "33cdae22bc" },
                  { "sessionId": "not-hex", "key": "zzzzzzzzzz" }
                ]
                """;

        List<String> problems = new ArrayList<>();
        List<SessionKey> imported = KeyStoreJson.importFrom(json, problems);

        assertEquals(1, imported.size());
        assertEquals("good", imported.get(0).sessionId());
        assertEquals(3, problems.size(), problems.toString());
    }

    @Test
    @DisplayName("reads numeric timestamps written without quotes")
    void readsBareNumbers() {
        String json = """
                [ { "sessionId": "s", "key": "33cdae22bc", "firstSeen": 1700000000000,
                    "lastSeen": 1700000009999, "source": "imported" } ]
                """;

        List<SessionKey> imported = KeyStoreJson.importFrom(json, null);

        assertEquals(1, imported.size());
        assertEquals(1700000000000L, imported.get(0).firstSeen());
        assertEquals(1700000009999L, imported.get(0).lastSeen());
        assertEquals(KeySource.IMPORTED, imported.get(0).source());
    }

    @Test
    @DisplayName("refuses junk without throwing")
    void refusesJunk() {
        assertTrue(KeyStoreJson.importFrom("", null).isEmpty());
        assertTrue(KeyStoreJson.importFrom(null, null).isEmpty());
        assertTrue(KeyStoreJson.importFrom("not json at all", null).isEmpty());
        assertTrue(KeyStoreJson.importFrom("{{{{[[[[", null).isEmpty());
        assertTrue(KeyStoreJson.importFrom("[{\"sessionId\":\"unterminated", null).isEmpty());
    }

    @Test
    @DisplayName("a very large input is refused rather than parsed")
    void refusesOversizedInput() {
        List<String> problems = new ArrayList<>();
        String huge = "[".repeat(5 * 1024 * 1024);

        assertTrue(KeyStoreJson.importFrom(huge, problems).isEmpty());
        assertFalse(problems.isEmpty());
    }
}
