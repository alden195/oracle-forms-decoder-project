package oracleforms.burp.history;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import oracleforms.burp.FormsDetector;
import oracleforms.session.Handshake;
import oracleforms.session.KeyDerivation;
import oracleforms.session.KeySource;
import oracleforms.session.Pragma3SelfTest;
import oracleforms.session.SessionKey;
import oracleforms.session.SessionKeyStore;
import oracleforms.session.StreamReplayer;

/**
 * Recovers session keys from Pragma 1 handshakes already sitting in proxy history.
 *
 * <p>This is what makes traffic captured before the extension was installed decodable, so it is the
 * other half of the headline feature. It is run <em>on demand</em> from the Sessions tab and never
 * automatically at load: history can be enormous, and walking it is not something to do behind the
 * user's back while Burp starts (BApp criterion 9).
 *
 * <p>Never call this on the EDT.
 */
public final class RetroactiveKeyScanner {

    /**
     * @param sessionsSeen     sessions with a Pragma 1 handshake found in history
     * @param keysRecovered    keys derived and stored
     * @param alreadyKnown     sessions skipped because a key was already stored
     * @param incomplete       sessions whose handshake was only half captured
     * @param symmetryFailures sessions where the Pragma 3 structural check failed
     * @param report           human-readable detail, one line per session
     */
    public record ScanResult(
            int sessionsSeen,
            int keysRecovered,
            int alreadyKnown,
            int incomplete,
            int symmetryFailures,
            String report) {
    }

    /** One session's handshake and first encrypted bodies, gathered during the scan. */
    private static final class Candidate {
        byte[] pragma1Request;
        byte[] pragma1Response;
        byte[] pragma3Request;
        byte[] pragma3Response;
        String host = "";
        long firstSeen = Long.MAX_VALUE;
        long lastSeen;
    }

    private final MontoyaApi api;
    private final SessionKeyStore keyStore;
    private final KeyDerivation derivation;

    public RetroactiveKeyScanner(
            MontoyaApi api, SessionKeyStore keyStore, KeyDerivation derivation) {
        this.api = api;
        this.keyStore = keyStore;
        this.derivation = derivation;
    }

    /**
     * Scans history and stores every key it can derive.
     *
     * @param overwriteExisting whether to replace keys already in the store
     */
    public ScanResult scan(boolean overwriteExisting) {
        Map<String, Candidate> candidates = collect();

        StringBuilder report = new StringBuilder();
        int recovered = 0;
        int known = 0;
        int incomplete = 0;
        int symmetryFailures = 0;

        for (Map.Entry<String, Candidate> entry : candidates.entrySet()) {
            String sessionId = entry.getKey();
            Candidate candidate = entry.getValue();

            if (!overwriteExisting && keyStore.contains(sessionId)) {
                known++;
                continue;
            }
            OptionalInt clientRandom = candidate.pragma1Request == null
                    ? OptionalInt.empty() : Handshake.clientRandom(candidate.pragma1Request);
            OptionalInt serverRandom = candidate.pragma1Response == null
                    ? OptionalInt.empty() : Handshake.serverRandom(candidate.pragma1Response);

            if (clientRandom.isEmpty() || serverRandom.isEmpty()) {
                incomplete++;
                report.append(sessionId)
                        .append(": handshake incomplete in history, no key derived\n");
                continue;
            }

            byte[] key = derivation.deriveKey(clientRandom.getAsInt(), serverRandom.getAsInt());

            // The structural check: do both directions really share a key and stream start? It
            // needs no plaintext, so it can run here, before anything is trusted.
            if (candidate.pragma3Request != null && candidate.pragma3Response != null) {
                Pragma3SelfTest.Result symmetry = Pragma3SelfTest.checkStreamSymmetry(
                        candidate.pragma3Request, candidate.pragma3Response);
                if (!symmetry.passed()) {
                    symmetryFailures++;
                    report.append(sessionId).append(": key stored, but the Pragma 3 check failed — ")
                            .append(symmetry.detail()).append('\n');
                } else {
                    report.append(sessionId).append(": key recovered; implied opening constant ")
                            .append(java.util.HexFormat.of().formatHex(
                                    Pragma3SelfTest.recoverOpeningConstant(
                                            key, candidate.pragma3Request)))
                            .append('\n');
                }
            } else {
                report.append(sessionId).append(": key recovered (no Pragma 3 captured to check)\n");
            }

            long firstSeen = candidate.firstSeen == Long.MAX_VALUE
                    ? System.currentTimeMillis() : candidate.firstSeen;
            keyStore.put(new SessionKey(sessionId, key, candidate.host,
                    firstSeen, candidate.lastSeen, "", KeySource.DERIVED));
            recovered++;
        }

        return new ScanResult(candidates.size(), recovered, known, incomplete, symmetryFailures,
                report.toString());
    }

    /** One pass over history, gathering the handshake and Pragma 3 bodies for every session. */
    private Map<String, Candidate> collect() {
        Map<String, Candidate> candidates = new LinkedHashMap<>();

        for (ProxyHttpRequestResponse item : api.proxy().history(
                candidate -> FormsDetector.isFormsPath(candidate.finalRequest()))) {
            try {
                Optional<FormsDetector.FormsTarget> detected =
                        FormsDetector.detect(item.finalRequest(), item.response());
                if (detected.isEmpty()) {
                    continue;
                }
                FormsDetector.FormsTarget target = detected.get();
                int pragma = target.pragma();
                if (pragma != Handshake.HANDSHAKE_PRAGMA
                        && pragma != StreamReplayer.FIRST_ENCRYPTED_PRAGMA) {
                    continue;
                }

                Candidate candidate =
                        candidates.computeIfAbsent(target.sessionId(), k -> new Candidate());
                candidate.host = item.httpService().host();

                long when = item.time().toInstant().toEpochMilli();
                candidate.firstSeen = Math.min(candidate.firstSeen, when);
                candidate.lastSeen = Math.max(candidate.lastSeen, when);

                byte[] requestBody = item.finalRequest().body().getBytes();
                byte[] responseBody =
                        item.response() == null ? null : item.response().body().getBytes();

                if (pragma == Handshake.HANDSHAKE_PRAGMA) {
                    // Take the body that actually carries the magic, not simply the first Pragma 1
                    // to turn up. The applet client numbers its `ifcmd=getinfo` GET Pragma 1 too,
                    // and that GET arrives *before* the GDay POST — so "first one wins" latches onto
                    // an empty body and the session is reported as having no handshake at all.
                    if (candidate.pragma1Request == null
                            && Handshake.clientRandom(requestBody).isPresent()) {
                        candidate.pragma1Request = requestBody;
                    }
                    if (candidate.pragma1Response == null && responseBody != null
                            && Handshake.serverRandom(responseBody).isPresent()) {
                        candidate.pragma1Response = responseBody;
                    }
                } else {
                    if (candidate.pragma3Request == null) {
                        candidate.pragma3Request = requestBody;
                    }
                    if (candidate.pragma3Response == null && responseBody != null) {
                        candidate.pragma3Response = responseBody;
                    }
                }
            } catch (RuntimeException e) {
                api.logging().logToError("Oracle Forms: skipping a history item during scan: " + e);
            }
        }
        return candidates;
    }
}
