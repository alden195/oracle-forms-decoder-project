package oracleforms.burp.repeater;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import oracleforms.burp.DecodeService;
import oracleforms.burp.FormsDetector;
import oracleforms.session.Direction;

/**
 * "Send decoded to Repeater" — the way a captured message becomes an editable draft.
 *
 * <p>What lands in Repeater is the message's <em>plaintext</em> plus the marker headers
 * (architecture &sect;6.5), so the raw tab is a hex editor over real FHT and the Oracle Forms tab can
 * edit it structurally. The encryption happens later, in
 * {@link RepeaterSendInterceptor}, at the only moment the right keystream offset is knowable.
 *
 * <p>Two menu items rather than one, because the send mode is never chosen on the user's behalf: one
 * appends to a live session and one does not.
 */
public final class SendToRepeaterMenu implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final DecodeService decodeService;

    public SendToRepeaterMenu(MontoyaApi api, DecodeService decodeService) {
        this.api = api;
        this.decodeService = decodeService;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        Optional<HttpRequestResponse> selected = selection(event);
        if (selected.isEmpty()) {
            return List.of();
        }
        HttpRequestResponse message = selected.get();

        Optional<FormsDetector.FormsTarget> target = FormsDetector.detect(
                message.request(), message.hasResponse() ? message.response() : null);
        if (target.isEmpty() || !target.get().isEncrypted()) {
            return List.of();
        }

        List<Component> items = new ArrayList<>(2);
        items.add(item("Send decoded to Repeater (append to live session)",
                "Encrypts at the session's current position when you send, so the server will act "
                        + "on it. This changes the state of a running application session.",
                message, target.get(), SendMode.TAIL));
        items.add(item("Send decoded to Repeater (original offset, for inspection)",
                "Encrypts at the offset this message originally occupied. Useful for comparing "
                        + "ciphertext; the server will not accept it unless this is the last "
                        + "message of the session.",
                message, target.get(), SendMode.OFFSET));
        return items;
    }

    private JMenuItem item(
            String label, String tooltip, HttpRequestResponse message,
            FormsDetector.FormsTarget target, SendMode mode) {

        JMenuItem menuItem = new JMenuItem(label);
        menuItem.setToolTipText(tooltip);
        menuItem.addActionListener(e -> draft(message, target, mode));
        return menuItem;
    }

    /**
     * Decodes on the background executor and hands the result to Repeater on the EDT.
     *
     * <p>Decoding replays the session's RC4 stream from the nearest checkpoint, which is exactly the
     * kind of work that must not happen on the Swing thread (BApp criterion 5).
     */
    private void draft(
            HttpRequestResponse message, FormsDetector.FormsTarget target, SendMode mode) {

        byte[] rawBody = message.request().body().getBytes();
        decodeService.plaintextOf(target, Direction.REQUEST, rawBody)
                .thenAccept(plaintext -> SwingUtilities.invokeLater(
                        () -> deliver(message, target, mode, plaintext)));
    }

    private void deliver(
            HttpRequestResponse message, FormsDetector.FormsTarget target, SendMode mode,
            DecodeService.Plaintext plaintext) {

        if (!plaintext.ok()) {
            JOptionPane.showMessageDialog(
                    api.userInterface().swingUtils().suiteFrame(),
                    "This message could not be decoded, so there is nothing to edit.\n\n"
                            + plaintext.failure(),
                    "Oracle Forms Decoder",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        HttpRequest draft = new DraftMarkers(target.sessionId(), mode, target.pragma())
                .applyTo(message.request().withBody(ByteArray.byteArray(plaintext.bytes())));

        api.repeater().sendToRepeater(draft,
                "Forms p" + target.pragma() + " " + shortSession(target.sessionId()));
        api.logging().logToOutput("Oracle Forms: drafted pragma " + target.pragma()
                + " of session " + target.sessionId() + " to Repeater in "
                + mode.wireName() + " mode.");
    }

    /**
     * The selected message: whatever the user right-clicked, whether a history row or a message
     * editor. Only a single selection is offered — drafting several at once would produce several
     * tabs all claiming the same tail position.
     */
    private static Optional<HttpRequestResponse> selection(ContextMenuEvent event) {
        try {
            if (event.messageEditorRequestResponse().isPresent()) {
                return Optional.of(event.messageEditorRequestResponse().get().requestResponse());
            }
            List<HttpRequestResponse> selected = event.selectedRequestResponses();
            return selected.size() == 1 ? Optional.of(selected.get(0)) : Optional.empty();
        } catch (RuntimeException e) {
            return Optional.empty();
        }
    }

    /** Enough of a JSESSIONID to tell two tabs apart without filling the tab strip. */
    private static String shortSession(String sessionId) {
        return sessionId.length() <= 8 ? sessionId : sessionId.substring(0, 8);
    }
}
