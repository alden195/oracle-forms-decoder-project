package oracleforms.burp;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import burp.api.montoya.MontoyaApi;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Smoke test for the load and unload cycle.
 *
 * <p>Everything else in the suite tests logic in isolation; this exercises the one path that has to
 * work before any of it matters — {@code initialize()} running to completion, and the unloading
 * handler tearing down cleanly afterwards. A wiring mistake, a null from the API, a Swing component
 * built on the wrong thread or a thread left running would all show up here rather than in Burp.
 *
 * <p>The API is supplied by a reflective proxy rather than a mocking library, keeping the project
 * dependency-free (BApp criterion 4). Every interface-returning call yields another proxy, so the
 * whole {@code api.userInterface().swingUtils()…} chain resolves without a running Burp.
 */
class ExtensionLifecycleTest {

    /** Records which API methods the extension actually called, so registrations can be asserted. */
    private static final class ApiRecorder implements InvocationHandler {

        private final List<String> calls = new CopyOnWriteArrayList<>();
        private final Map<Class<?>, Object> proxies = new ConcurrentHashMap<>();

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) {
            calls.add(method.getName());

            Class<?> returnType = method.getReturnType();

            if (returnType == void.class) {
                return null;
            }
            if (returnType == boolean.class) {
                return false;
            }
            if (returnType == int.class || returnType == short.class || returnType == byte.class) {
                return 0;
            }
            if (returnType == long.class) {
                return 0L;
            }
            if (returnType == String.class) {
                return "";
            }
            if (returnType == Optional.class) {
                return Optional.empty();
            }
            if (Set.class.isAssignableFrom(returnType)) {
                return Set.of();
            }
            if (List.class.isAssignableFrom(returnType) || Collection.class == returnType) {
                return List.of();
            }
            if (returnType.isArray()) {
                return java.lang.reflect.Array.newInstance(returnType.getComponentType(), 0);
            }
            if (returnType.isInterface()) {
                return proxies.computeIfAbsent(returnType, this::newProxy);
            }
            return null;
        }

        private Object newProxy(Class<?> type) {
            return Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] {type}, this);
        }

        boolean called(String method) {
            return calls.contains(method);
        }
    }

    private static MontoyaApi stubApi(ApiRecorder recorder) {
        return (MontoyaApi) Proxy.newProxyInstance(
                MontoyaApi.class.getClassLoader(), new Class<?>[] {MontoyaApi.class}, recorder);
    }

    private static Set<String> extensionThreadNames() {
        return Thread.getAllStackTraces().keySet().stream()
                .map(Thread::getName)
                .filter(name -> name.startsWith("oracle-forms-"))
                .collect(java.util.stream.Collectors.toSet());
    }

    @Test
    @DisplayName("initialize() completes without throwing and registers everything")
    void initializesCleanly() {
        ApiRecorder recorder = new ApiRecorder();
        OracleFormsDecoder decoder = new OracleFormsDecoder();

        assertDoesNotThrow(() -> decoder.initialize(stubApi(recorder)));

        assertTrue(recorder.called("setName"), "the extension must name itself");
        assertTrue(recorder.called("registerHttpHandler"), "key capture must be registered");
        assertTrue(recorder.called("registerHttpRequestEditorProvider"));
        assertTrue(recorder.called("registerHttpResponseEditorProvider"));
        assertTrue(recorder.called("registerSuiteTab"), "the Sessions tab must be registered");
        assertTrue(recorder.called("registerUnloadingHandler"),
                "without this the extension cannot clean up (BApp criterion 6)");
    }

    /**
     * The template's entry point must still be the thing Burp finds, and it must delegate rather
     * than having quietly gone stale.
     */
    @Test
    @DisplayName("the Extension entry point loads and delegates")
    void entryPointWorks() throws Exception {
        ApiRecorder recorder = new ApiRecorder();

        // Loaded by name: this is exactly how Burp finds it, so the test also pins the class down to
        // the jar root under the expected name. A test in this package cannot import a class in the
        // default package, hence the reflection.
        Class<?> entryPoint = Class.forName("Extension");
        assertTrue(burp.api.montoya.BurpExtension.class.isAssignableFrom(entryPoint),
                "Burp only loads classes implementing BurpExtension");

        Object instance = entryPoint.getDeclaredConstructor().newInstance();
        entryPoint.getMethod("initialize", MontoyaApi.class).invoke(instance, stubApi(recorder));

        assertTrue(recorder.called("setName"));
    }

    /**
     * BApp criterion 6. Threads left running after unload are the classic extension leak, and the
     * reference implementation had no unload handling whatsoever.
     */
    @Test
    @DisplayName("unloading stops every thread the extension started")
    void unloadStopsAllThreads() throws Exception {
        ApiRecorder recorder = new ApiRecorder();
        OracleFormsDecoder decoder = new OracleFormsDecoder();
        decoder.initialize(stubApi(recorder));

        // Prove the threads existed first, otherwise "none running afterwards" is trivially true and
        // the test asserts nothing.
        long started = System.currentTimeMillis() + 5000;
        while (extensionThreadNames().isEmpty() && System.currentTimeMillis() < started) {
            Thread.sleep(20);
        }
        assertFalse(extensionThreadNames().isEmpty(),
                "expected the extension to have started background threads before unload");

        decoder.unloadForTesting();

        // Shutdown is asynchronous; give the pools a moment to actually die.
        long deadline = System.currentTimeMillis() + 5000;
        while (!extensionThreadNames().isEmpty() && System.currentTimeMillis() < deadline) {
            Thread.sleep(50);
        }

        assertTrue(extensionThreadNames().isEmpty(),
                "threads still running after unload: " + extensionThreadNames());
    }

    @Test
    @DisplayName("unloading twice is harmless")
    void doubleUnloadIsSafe() {
        ApiRecorder recorder = new ApiRecorder();
        OracleFormsDecoder decoder = new OracleFormsDecoder();
        decoder.initialize(stubApi(recorder));

        assertDoesNotThrow(decoder::unloadForTesting);
        assertDoesNotThrow(decoder::unloadForTesting);
    }

    /**
     * A load/unload/load cycle is the normal development loop — CLAUDE.md tells the user to reload
     * by Ctrl-clicking the Loaded checkbox — so it must not accumulate state or fail the second time.
     */
    @Test
    @DisplayName("load / unload / load survives the reload cycle")
    void reloadCycle() {
        for (int i = 0; i < 3; i++) {
            ApiRecorder recorder = new ApiRecorder();
            OracleFormsDecoder decoder = new OracleFormsDecoder();

            int attempt = i;
            assertDoesNotThrow(() -> decoder.initialize(stubApi(recorder)),
                    "load attempt " + attempt + " failed");
            assertDoesNotThrow(decoder::unloadForTesting, "unload attempt " + attempt + " failed");
        }
        assertFalse(Thread.currentThread().isInterrupted());
    }
}
