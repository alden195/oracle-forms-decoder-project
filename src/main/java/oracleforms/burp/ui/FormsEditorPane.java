package oracleforms.burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.RawEditor;
import java.awt.Component;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicLong;
import javax.swing.SwingUtilities;
import oracleforms.burp.DecodeService;
import oracleforms.burp.FormsDetector;
import oracleforms.session.Direction;

/**
 * The shared body of the request and response editor tabs.
 *
 * <p>Both tabs do the same thing with a different {@link Direction}, so the logic lives here and the
 * two {@code ExtensionProvided*Editor} implementations are thin adapters over it.
 *
 * <p>The threading contract is the point of this class. {@code setRequestResponse} is called on the
 * EDT, so it does nothing but show a pending message and hand the work to
 * {@link DecodeService}; the result is applied back on the EDT when it arrives. A generation counter
 * discards results that land after the user has already moved to another message — without it, a
 * slow decode of a large Pragma 3 response would overwrite whatever the user is looking at now.
 */
final class FormsEditorPane {

    private final MontoyaApi api;
    private final DecodeService decodeService;
    private final Direction direction;
    private final RawEditor editor;

    /** Incremented on every message shown; stale results are dropped. */
    private final AtomicLong generation = new AtomicLong();

    FormsEditorPane(MontoyaApi api, DecodeService decodeService, Direction direction) {
        this.api = api;
        this.decodeService = decodeService;
        this.direction = direction;
        this.editor = api.userInterface().createRawEditor(
                EditorOptions.READ_ONLY, EditorOptions.WRAP_LINES);
    }

    Component uiComponent() {
        return editor.uiComponent();
    }

    Selection selectedData() {
        return editor.selection().orElse(null);
    }

    /** Shows a message: pending state now, decoded text when the background work finishes. */
    void show(FormsDetector.FormsTarget target, byte[] body) {
        long mine = generation.incrementAndGet();

        setText("Decoding pragma " + target.pragma() + " of session " + target.sessionId() + "...\n\n"
                + "Replaying the RC4 stream from the start of the session.");

        decodeService.decode(target, direction, body).thenAccept(result -> {
            if (generation.get() != mine) {
                return; // The user has moved on; this result is for a message no longer displayed.
            }
            SwingUtilities.invokeLater(() -> {
                if (generation.get() == mine) {
                    setText(result.text());
                }
            });
        });
    }

    /** Shows a message that could not even be identified as Forms traffic. */
    void showNotApplicable(String reason) {
        generation.incrementAndGet();
        setText(reason);
    }

    private void setText(String text) {
        try {
            // UTF-8, not ISO-8859-1. FHT string properties are decoded from UTF-8 on the wire, so
            // they can hold any character; ISO-8859-1 silently replaces everything outside Latin-1
            // with '?', which would corrupt real decoded values, not just decoration. The renderer
            // keeps its own decoration to plain ASCII so the layout survives whatever display
            // charset Burp is configured with.
            editor.setContents(ByteArray.byteArray(text.getBytes(StandardCharsets.UTF_8)));
        } catch (RuntimeException e) {
            api.logging().logToError("Oracle Forms: could not update the editor: " + e);
        }
    }
}
