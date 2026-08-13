package oracleforms.session;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Runs the key-derivation validator against bytes from the real target.
 *
 * <h2>How to make this test actually run</h2>
 *
 * <p>It skips unless a fixture file is present, because the repository does not carry one — the
 * fixtures contain live session secrets, and not every machine has ever seen the target. To produce
 * one:
 *
 * <ol>
 *   <li>Load the extension in Burp against a project that has Forms traffic.
 *   <li>Sessions tab &rarr; <em>Export validation fixtures…</em>.
 *   <li>Either save it to {@link #DEFAULT_FIXTURE_PATH}, or run
 *       {@code ./gradlew test -Doracleforms.fixtures=/path/to/oracle-forms-fixtures.json}.
 * </ol>
 *
 * <h2>What a pass means</h2>
 *
 * <p>This is the check the project has been missing since the beginning. Every other test builds its
 * own session with {@link GdayMateKeyDerivation}, so they prove the code is self-consistent and
 * nothing more — if the derivation formula is wrong, they all still pass. This one starts from
 * ciphertext the extension never produced, so it can genuinely fail.
 *
 * <p>Two independent things have to hold, and {@link KeyValidation#crossCheck} requires both: every
 * session's derived key must out-parse random keys on that session's own ciphertext, and every
 * session must recover the same FHT opening constant despite having different randoms and therefore
 * different keys. Whatever constant they agree on is the value architecture §8 lists as unknown, so a
 * pass here also answers that question as a by-product.
 */
class RealCaptureValidationTest {

    /** Where the test looks when no system property is set. */
    static final String DEFAULT_FIXTURE_PATH = "src/test/resources/fixtures/oracle-forms-fixtures.json";

    private static final String FIXTURE_PROPERTY = "oracleforms.fixtures";

    private static Path fixturePath() {
        String configured = System.getProperty(FIXTURE_PROPERTY);
        return Path.of(configured == null ? DEFAULT_FIXTURE_PATH : configured);
    }

    @Test
    @DisplayName("the GDay/Mate derivation holds up against real captured sessions")
    void derivationHoldsAgainstRealCapture() throws IOException {
        Path path = fixturePath();
        assumeTrue(Files.isReadable(path),
                "No capture fixtures at " + path.toAbsolutePath() + ". Export them from the "
                        + "Sessions tab (\"Export validation fixtures…\") or pass -D"
                        + FIXTURE_PROPERTY + "=<path>. Until then the derivation is unvalidated: "
                        + "every other test builds its session with the same formula it is checking.");

        List<String> problems = new ArrayList<>();
        List<ValidationFixtures.Fixture> fixtures = ValidationFixtures.importFrom(
                Files.readString(path, StandardCharsets.UTF_8), problems);

        assertTrue(problems.isEmpty(), "fixture file had problems: " + problems);

        List<ValidationFixtures.Fixture> usable =
                fixtures.stream().filter(ValidationFixtures.Fixture::isComplete).toList();
        assumeTrue(!usable.isEmpty(),
                "The fixture file has " + fixtures.size() + " session(s) but none carries both a "
                        + "handshake and a pragma 3 body, so there is nothing to validate.");

        KeyDerivation derivation = new GdayMateKeyDerivation();
        List<KeyValidation.Evidence> evidence = usable.stream()
                .map(f -> KeyValidation.validate(f.sessionId(), derivation,
                        f.pragma1Request(), f.pragma1Response(), f.pragma3Request()))
                .toList();

        KeyValidation.Verdict verdict = KeyValidation.crossCheck(evidence);

        StringBuilder report = new StringBuilder(verdict.detail()).append("\n\nPer session:\n");
        for (KeyValidation.Evidence e : evidence) {
            report.append("  ").append(e.describe()).append('\n');
        }
        assertTrue(verdict.validated(), report.toString());
    }

    /**
     * The keyless half of the evidence, kept separate because it can run even when no key can be
     * derived — and because if it fails, the replay model is wrong in a way no key would fix.
     */
    @Test
    @DisplayName("both directions share a key and a stream start, on real sessions")
    void streamSymmetryHoldsAgainstRealCapture() throws IOException {
        Path path = fixturePath();
        assumeTrue(Files.isReadable(path), "No capture fixtures at " + path.toAbsolutePath());

        List<ValidationFixtures.Fixture> fixtures = ValidationFixtures.importFrom(
                Files.readString(path, StandardCharsets.UTF_8), new ArrayList<>());

        List<ValidationFixtures.Fixture> usable = fixtures.stream()
                .filter(f -> f.pragma3Request().length >= Pragma3SelfTest.PREFIX_LENGTH
                        && f.pragma3Response().length >= Pragma3SelfTest.PREFIX_LENGTH)
                .toList();
        assumeTrue(!usable.isEmpty(), "no session carries both pragma 3 bodies");

        List<String> failures = new ArrayList<>();
        for (ValidationFixtures.Fixture fixture : usable) {
            Pragma3SelfTest.Result result = Pragma3SelfTest.checkStreamSymmetry(
                    fixture.pragma3Request(), fixture.pragma3Response());
            if (!result.passed()) {
                failures.add(fixture.sessionId() + ": " + result.detail());
            }
        }

        assertTrue(failures.isEmpty(),
                "the two directions do not share a key and stream start in "
                        + failures.size() + " of " + usable.size() + " sessions:\n"
                        + String.join("\n", failures));
    }
}
