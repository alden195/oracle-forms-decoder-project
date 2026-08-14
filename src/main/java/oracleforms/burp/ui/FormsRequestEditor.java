package oracleforms.burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import java.awt.CardLayout;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import javax.swing.JPanel;
import oracleforms.burp.DecodeService;
import oracleforms.burp.FormsDetector;
import oracleforms.burp.FhtRenderer;
import oracleforms.burp.repeater.DraftMarkers;
import oracleforms.burp.repeater.SendMode;
import oracleforms.codec.FhtParser;
import oracleforms.codec.StringDictionary;
import oracleforms.codec.model.FhtPacket;
import oracleforms.session.Direction;
import oracleforms.session.ReplayResult;

/**
 * The "Oracle Forms" tab on a request.
 *
 * <p>Two modes, and which one applies is decided by the message rather than by a setting:
 *
 * <ul>
 *   <li><b>A captured message</b> is decoded read-only, by replaying the session's RC4 stream.
 *   <li><b>A plaintext draft</b> — one carrying the {@code X-OracleForms-*} markers, which is what
 *       "Send decoded to Repeater" produces — is parsed straight from the body and its properties
 *       are editable. There is nothing to replay: the body is already clear.
 * </ul>
 *
 * <p>Editing is additionally gated on the editor being writable at all, which Burp decides. Proxy
 * history is created {@code READ_ONLY}, so it stays read-only for free and the editable path can
 * only appear where an edit could mean something (architecture &sect;6.6).
 */
public final class FormsRequestEditor implements ExtensionProvidedHttpRequestEditor {

    private static final String DECODED_VIEW = "decoded";
    private static final String DRAFT_VIEW = "draft";

    private final MontoyaApi api;
    private final FormsEditorPane pane;
    private final FhtDraftPanel draftPanel = new FhtDraftPanel();
    private final JPanel cards = new JPanel(new CardLayout());
    private final boolean editable;

    private HttpRequestResponse current;
    private DraftMarkers draft;

    public FormsRequestEditor(MontoyaApi api, DecodeService decodeService, boolean editable) {
        this.api = api;
        this.editable = editable;
        this.pane = new FormsEditorPane(api, decodeService, Direction.REQUEST);
        cards.add(pane.uiComponent(), DECODED_VIEW);
        cards.add(draftPanel.uiComponent(), DRAFT_VIEW);
    }

    /**
     * The request as it should now stand.
     *
     * <p>For a draft this is the body with the user's edits spliced in — still plaintext. It is
     * <em>not</em> encrypted here: Burp calls this whenever it wants the message, and the keystream
     * offset a send needs is not knowable until the request actually leaves. That happens in the
     * HTTP handler (architecture &sect;6.5).
     */
    @Override
    public HttpRequest getRequest() {
        if (current == null) {
            return null;
        }
        if (draft == null) {
            return current.request();
        }

        List<String> problem = new ArrayList<>(1);
        byte[] edited = draftPanel.editedPlaintext(problem);
        if (!problem.isEmpty()) {
            api.logging().logToError(
                    "Oracle Forms: could not apply an edit, sending the message unchanged: "
                            + problem.get(0));
        }
        return current.request().withBody(ByteArray.byteArray(edited));
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        this.current = requestResponse;
        this.draft = null;

        Optional<FormsDetector.FormsTarget> target = FormsDetector.detect(
                requestResponse.request(),
                requestResponse.hasResponse() ? requestResponse.response() : null);
        if (target.isEmpty()) {
            show(DECODED_VIEW);
            pane.showNotApplicable("This request is not an identifiable Oracle Forms message.");
            return;
        }

        Optional<DraftMarkers> markers = DraftMarkers.from(requestResponse.request());
        if (markers.isPresent()) {
            this.draft = markers.get();
            showDraft(markers.get(), requestResponse.request().body().getBytes());
            return;
        }

        show(DECODED_VIEW);
        pane.show(target.get(), requestResponse.request().body().getBytes());
    }

    /**
     * Renders a draft from its own body.
     *
     * <p>Parsing is cheap — no replay, no history scan — so unlike the decode path this can happen
     * inline on the EDT.
     */
    private void showDraft(DraftMarkers markers, byte[] plaintext) {
        FhtPacket packet = new FhtParser().parse(plaintext, new StringDictionary());
        String rendered = FhtRenderer.render(packet,
                "Draft for session " + markers.sessionId(), plaintext,
                new ReplayResult.FragmentGroup(
                        markers.originPragma(), markers.originPragma(), markers.originPragma(), true));

        draftPanel.show(plaintext, headerFor(markers, plaintext), rendered, editable);
        show(DRAFT_VIEW);
    }

    /**
     * The banner above the table.
     *
     * <p>It says what mode the draft is in and what that mode does, because the difference between
     * "append to a live session" and "encrypt at a historical offset" is the difference between
     * changing somebody's running application and not.
     */
    private String headerFor(DraftMarkers markers, byte[] plaintext) {
        String modeLine = markers.mode() == SendMode.TAIL
                ? "<b>Append to live session.</b> On Send this is encrypted at the session's current "
                        + "keystream position and the Forms runtime will act on it. This changes the "
                        + "state of a running application session."
                : "<b>Original offset — for inspection.</b> On Send this is encrypted at the offset "
                        + "pragma " + markers.originPragma() + " originally occupied. The server will "
                        + "not accept it unless that is still the session's last message.";

        return "<html><body style='width: 640px'>"
                + "Oracle Forms draft &mdash; session <code>" + escape(markers.sessionId())
                + "</code>, from pragma " + markers.originPragma()
                + ", " + plaintext.length + " plaintext bytes<br>"
                + modeLine
                + (editable
                        ? "<br>Edit a value in the table below, then Send."
                        : "<br><i>This view is read-only. Send the message to Repeater to edit it.</i>")
                + "</body></html>";
    }

    private static String escape(String text) {
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private void show(String card) {
        ((CardLayout) cards.getLayout()).show(cards, card);
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        try {
            return requestResponse != null
                    && requestResponse.request() != null
                    && FormsDetector.detect(requestResponse.request()).isPresent();
        } catch (RuntimeException e) {
            return false;
        }
    }

    @Override
    public String caption() {
        return "Oracle Forms";
    }

    @Override
    public Component uiComponent() {
        return cards;
    }

    @Override
    public Selection selectedData() {
        return draft == null ? pane.selectedData() : null;
    }

    @Override
    public boolean isModified() {
        return draft != null && draftPanel.isModified();
    }
}
