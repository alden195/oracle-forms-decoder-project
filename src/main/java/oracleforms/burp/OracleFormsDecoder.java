package oracleforms.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import javax.swing.SwingUtilities;
import oracleforms.burp.handler.FormsHttpHandler;
import oracleforms.burp.persistence.PersistedKeyStore;
import oracleforms.burp.repeater.RepeaterSendInterceptor;
import oracleforms.burp.repeater.SendToRepeaterMenu;
import oracleforms.burp.ui.FormsEditorProviders;
import oracleforms.burp.ui.SessionsTab;
import oracleforms.session.DictionaryScope;
import oracleforms.session.GdayMateKeyDerivation;
import oracleforms.session.InMemorySessionKeyStore;
import oracleforms.session.KeyDerivation;
import oracleforms.session.SessionKeyStore;
import oracleforms.session.StreamPositionStore;
import oracleforms.session.StreamRegistry;

/**
 * Wires the decoder together and takes it apart again.
 *
 * <p>The dependency direction from architecture &sect;4 is visible here: this class knows about
 * Montoya and constructs everything, while {@code codec} and {@code session} know nothing about Burp
 * and are handed only plain values.
 *
 * <p>Unloading is handled explicitly, which the reference implementation did not do at all
 * (BApp criterion 6): every registration is undone, the decode executor and the Sessions tab worker
 * are shut down, and all caches are dropped.
 */
public final class OracleFormsDecoder {

    private static final String EXTENSION_NAME = "Oracle Forms Decoder";

    /**
     * Whether the string dictionary is per packet or per session is still an open question
     * (architecture &sect;7.2). The reference resets per packet, so that is the default until a real
     * session is decoded and the answer is visible.
     */
    private static final DictionaryScope DICTIONARY_SCOPE = DictionaryScope.PACKET;

    /** Colour and comment Forms traffic in the proxy history so it is findable. */
    private static final boolean ANNOTATE_HISTORY = true;

    private final List<Registration> registrations = new ArrayList<>();

    private DecodeService decodeService;
    private FormsHttpHandler httpHandler;
    private SessionsTab sessionsTab;
    private StreamRegistry streamRegistry;
    private RepeaterSendInterceptor sendInterceptor;
    private MontoyaApi lastApi;

    public void initialize(MontoyaApi api) {
        this.lastApi = api;
        api.extension().setName(EXTENSION_NAME);

        KeyDerivation derivation = new GdayMateKeyDerivation();
        SessionKeyStore keyStore = openKeyStore(api);

        decodeService = new DecodeService(api, keyStore, DICTIONARY_SCOPE);
        streamRegistry = new StreamRegistry(streamPositionStore(keyStore));
        sendInterceptor = new RepeaterSendInterceptor(
                keyStore, streamRegistry, decodeService::historyFor, decodeService, api.logging());
        httpHandler = new FormsHttpHandler(
                keyStore, derivation, api.logging(), ANNOTATE_HISTORY, sendInterceptor,
                streamRegistry);
        sessionsTab = buildSessionsTab(api, keyStore, derivation);

        registrations.add(api.http().registerHttpHandler(httpHandler));
        registrations.add(api.userInterface().registerContextMenuItemsProvider(
                new SendToRepeaterMenu(api, decodeService)));
        registrations.add(api.userInterface().registerHttpRequestEditorProvider(
                FormsEditorProviders.requestProvider(api, decodeService)));
        registrations.add(api.userInterface().registerHttpResponseEditorProvider(
                FormsEditorProviders.responseProvider(api, decodeService)));
        if (sessionsTab != null) {
            registrations.add(api.userInterface().registerSuiteTab("Oracle Forms", sessionsTab));
        } else {
            // Decoding still works without the key-management UI, so a failed tab must not take the
            // whole extension down with it.
            api.logging().logToError("Oracle Forms: the Sessions tab could not be created; "
                    + "decoding is unaffected, but key management is unavailable.");
        }

        registrations.add(api.extension().registerUnloadingHandler(new Unloader(api)));

        api.logging().logToOutput(EXTENSION_NAME + " loaded. "
                + keyStore.size() + " session key(s) in this project.");
    }

    /**
     * Builds the Sessions tab on the Event Dispatch Thread.
     *
     * <p>Burp calls {@code initialize} on a background thread, and Swing components must be created
     * on the EDT. Building them off it is the kind of violation that works nine times and then
     * deadlocks or paints garbage on the tenth, on someone else's machine.
     */
    private SessionsTab buildSessionsTab(
            MontoyaApi api, SessionKeyStore keyStore, KeyDerivation derivation) {

        if (SwingUtilities.isEventDispatchThread()) {
            return new SessionsTab(api, keyStore, decodeService, derivation);
        }
        AtomicReference<SessionsTab> built = new AtomicReference<>();
        try {
            SwingUtilities.invokeAndWait(
                    () -> built.set(new SessionsTab(api, keyStore, decodeService, derivation)));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (InvocationTargetException e) {
            api.logging().logToError("Oracle Forms: could not build the Sessions tab: " + e.getCause());
        }
        return built.get();
    }

    /**
     * The stream-position store, when the key store is one.
     *
     * <p>The in-memory fallback is not, and that is the right answer rather than an omission: if the
     * project file could not be opened there is nowhere durable to record a divergence, and
     * pretending otherwise would promise a ledger that silently vanishes on reload.
     */
    private static StreamPositionStore streamPositionStore(SessionKeyStore keyStore) {
        return keyStore instanceof StreamPositionStore store ? store : StreamPositionStore.none();
    }

    /**
     * Opens the persisted store, falling back to memory if the project file cannot be used.
     *
     * <p>A session that decodes until Burp restarts beats an extension that refuses to load.
     */
    private SessionKeyStore openKeyStore(MontoyaApi api) {
        try {
            PersistedKeyStore store =
                    new PersistedKeyStore(api.persistence().extensionData(), api.logging());
            store.list(); // Touch it once so a broken store fails here, not mid-decode.
            return store;
        } catch (RuntimeException e) {
            api.logging().logToError("Oracle Forms: could not open the persisted key store, "
                    + "falling back to in-memory keys for this session: " + e);
            return new InMemorySessionKeyStore();
        }
    }

    private final class Unloader implements ExtensionUnloadingHandler {

        private final MontoyaApi api;

        private Unloader(MontoyaApi api) {
            this.api = api;
        }

        @Override
        public void extensionUnloaded() {
            tearDown(api);
        }
    }

    /**
     * Releases everything the extension holds.
     *
     * <p>Written to be safe to call more than once: Burp can unload an extension that failed partway
     * through loading, so every field here may legitimately be null, and a second call must be a
     * no-op rather than an error.
     */
    void tearDown(MontoyaApi api) {
        for (Registration registration : registrations) {
            try {
                if (registration.isRegistered()) {
                    registration.deregister();
                }
            } catch (RuntimeException e) {
                api.logging().logToError("Oracle Forms: failed to deregister: " + e);
            }
        }
        registrations.clear();

        if (httpHandler != null) {
            httpHandler.shutdown();
            httpHandler = null;
        }
        if (sendInterceptor != null) {
            sendInterceptor.shutdown();
            sendInterceptor = null;
        }
        if (streamRegistry != null) {
            streamRegistry.clear();
            streamRegistry = null;
        }
        if (sessionsTab != null) {
            sessionsTab.shutdown();
            sessionsTab = null;
        }
        if (decodeService != null) {
            decodeService.shutdown();
            decodeService = null;
        }
        api.logging().logToOutput(EXTENSION_NAME + " unloaded.");
    }

    /** Test hook for the load/unload lifecycle; production unloading goes through {@link Unloader}. */
    void unloadForTesting() {
        tearDown(lastApi);
    }
}
