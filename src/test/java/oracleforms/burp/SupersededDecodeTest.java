package oracleforms.burp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import burp.api.montoya.MontoyaApi;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import oracleforms.session.Direction;
import oracleforms.session.DictionaryScope;
import oracleforms.session.SessionKey;
import oracleforms.session.SessionKeyStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * A late, better reading of a body must be able to reach the screen.
 *
 * <h2>The bug this pins</h2>
 *
 * <p>The reply to a Repeater send is decoded twice: once immediately at the ledger's keystream
 * offset, and then — only if that reads as noise — again on the decode executor at the offset
 * {@link oracleforms.session.ReplyOffsetRecovery} solves for, seconds later.
 *
 * <p>Both write the same {@link DecodedBodyCache} entry, but nothing connected the second write to
 * the display. {@link DecodeService#decode} caches the <em>rendered text</em> under
 * (session, direction, pragma) and that cache never expires within a project, so the first,
 * unreadable rendering was served for the life of the project — closing and reopening the message
 * showed it again — while the corrected plaintext sat in a cache nothing consulted a second time.
 * The recovery was therefore invisible whether or not it worked, which is exactly what
 * "I got the same error" looks like from outside.
 */
class SupersededDecodeTest {

    private static final String SESSION = "JSESSIONID-under-test!-1111111111";
    private static final int PRAGMA = 29;

    private DecodeService service;

    @AfterEach
    void tearDown() {
        if (service != null) {
            service.shutdown();
        }
    }

    /** A key store with nothing in it: these tests never reach the replay path. */
    private static SessionKeyStore emptyStore() {
        return new SessionKeyStore() {
            @Override
            public Optional<SessionKey> get(String sessionId) {
                return Optional.empty();
            }

            @Override
            public void put(SessionKey key) {
            }

            @Override
            public List<SessionKey> list() {
                return List.of();
            }

            @Override
            public boolean forget(String sessionId) {
                return false;
            }

            @Override
            public void clear() {
            }
        };
    }

    private static MontoyaApi stubApi() {
        return (MontoyaApi) Proxy.newProxyInstance(
                MontoyaApi.class.getClassLoader(),
                new Class<?>[] {MontoyaApi.class},
                (proxy, method, args) -> {
                    Class<?> type = method.getReturnType();
                    if (type == void.class) {
                        return null;
                    }
                    if (type.isInterface()) {
                        return Proxy.newProxyInstance(type.getClassLoader(),
                                new Class<?>[] {type}, (p, m, a) -> null);
                    }
                    return null;
                });
    }

    private DecodeService newService() {
        service = new DecodeService(stubApi(), emptyStore(), DictionaryScope.PACKET);
        return service;
    }

    private static String render(DecodeService service, byte[] body)
            throws ExecutionException, InterruptedException {
        return service.decode(new FormsDetector.FormsTarget(SESSION, PRAGMA),
                Direction.RESPONSE, body).get().text();
    }

    /**
     * A well-formed single-property FHT message, so the two readings render differently and the
     * assertion is about the text the user would see rather than about cache internals.
     */
    private static byte[] fht(int propertyId, int value) {
        return new byte[] {
                (byte) 0x14, 0x00,                                  // message header
                (byte) (propertyId >> 8), (byte) propertyId,        // property id
                0x10,                                               // type marker: 4-byte integer
                0, 0, 0, (byte) value,
                (byte) 0xF0,                                        // terminator
        };
    }

    @Test
    @DisplayName("a superseded reading is replaced in the rendered-result cache, not served forever")
    void supersededReadingIsNotServedForever() throws Exception {
        DecodeService service = newService();
        byte[] ciphertext = {1, 2, 3, 4, 5, 6, 7};

        byte[] first = fht(0x0102, 0x11);
        service.put(ciphertext, first);
        String before = render(service, ciphertext);

        // What the recovery does when it finds the real offset: same bytes on the wire, a different
        // reading of them.
        byte[] corrected = fht(0x0304, 0x22);
        service.put(ciphertext, corrected);
        String after = render(service, ciphertext);

        assertNotEquals(before, after,
                "the corrected reading must replace the one rendered from the ledger's offset");
        assertTrue(before.contains("MAX_LENGTH_IS_BYTES"), "sanity: the first reading rendered");
        assertTrue(after.contains("ID_1040"),
                "the rendering must come from the corrected plaintext, not the cached first pass");
    }

    @Test
    @DisplayName("open editors are told which message was re-decoded")
    void listenersAreNotifiedForTheRightMessage() throws Exception {
        DecodeService service = newService();
        byte[] ciphertext = {9, 8, 7, 6, 5};

        List<String> notified = new CopyOnWriteArrayList<>();
        DecodeService.DecodeUpdateListener listener =
                (session, direction, pragma) -> notified.add(session + "/" + direction + "/" + pragma);
        service.addUpdateListener(listener);

        service.put(ciphertext, fht(0x0102, 0x11));
        render(service, ciphertext);
        assertEquals(List.of(), notified, "the first reading supersedes nothing");

        service.put(ciphertext, fht(0x0304, 0x22));
        assertEquals(List.of(SESSION + "/RESPONSE/" + PRAGMA), notified,
                "the pane showing this message must be told to repaint");
    }

    @Test
    @DisplayName("re-putting identical bytes notifies nobody")
    void identicalBytesAreNotASupersede() throws Exception {
        DecodeService service = newService();
        byte[] ciphertext = {4, 4, 4, 4};

        List<String> notified = new ArrayList<>();
        DecodeService.DecodeUpdateListener listener =
                (session, direction, pragma) -> notified.add(session);
        service.addUpdateListener(listener);

        byte[] plaintext = fht(0x0102, 0x11);
        service.put(ciphertext, plaintext);
        render(service, ciphertext);
        service.put(ciphertext, plaintext.clone());

        assertEquals(List.of(), notified,
                "a repeat of the same reading is not a correction and must not repaint");
    }

    @Test
    @DisplayName("a body nothing has rendered yet needs no invalidation")
    void unrenderedBodyIsHarmless() {
        DecodeService service = newService();
        byte[] ciphertext = {1, 1, 1, 1};

        List<String> notified = new ArrayList<>();
        service.addUpdateListener((session, direction, pragma) -> notified.add(session));

        service.put(ciphertext, fht(0x0102, 0x11));
        service.put(ciphertext, fht(0x0304, 0x22));

        assertEquals(List.of(), notified,
                "nothing has displayed this body, so the next display picks up the newer reading");
        assertTrue(service.get(ciphertext).isPresent());
    }
}
