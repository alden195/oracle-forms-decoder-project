package oracleforms.burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import oracleforms.burp.proxy.InterceptEditService;
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
    private final FhtDraftPanel draftPanel;
    private final JPanel cards = new JPanel(new CardLayout());
    private final boolean editable;

    /** Present only where an in-flight edit could mean something: a held Proxy request. */
    private final InterceptEditService interceptService;

    private final JPanel decodedView = new JPanel(new BorderLayout());
    private final JPanel convertBar = new JPanel(new BorderLayout());
    private final JButton convertButton = new JButton("Edit this request");
    private final JLabel convertStatus = new JLabel(" ");

    /** Discards a preparation that lands after the user has moved to another message. */
    private final AtomicLong generation = new AtomicLong();

    private HttpRequestResponse current;
    private DraftMarkers draft;

    /** The message the conversion bar is currently offering to convert, if any. */
    private FormsDetector.FormsTarget interceptTarget;
    private InterceptEditService.Prepared prepared;

    /**
     * Whether the user has converted this held request into an editable draft.
     *
     * <p>Distinct from {@code draft != null}, which is also true for a Repeater tab that arrived
     * already marked. Only a conversion makes the request itself different from what Burp handed
     * us, and only that has to be reported through {@link #isModified()}.
     */
    private boolean converted;

    public FormsRequestEditor(MontoyaApi api, DecodeService decodeService, boolean editable) {
        this(api, decodeService, editable, null);
    }

    public FormsRequestEditor(
            MontoyaApi api, DecodeService decodeService, boolean editable,
            InterceptEditService interceptService) {

        this.api = api;
        this.editable = editable;
        this.interceptService = interceptService;
        this.draftPanel = new FhtDraftPanel(api);
        this.pane = new FormsEditorPane(api, decodeService, Direction.REQUEST);

        convertButton.addActionListener(e -> convertToDraft());
        convertButton.setToolTipText("Decode this request into an editable draft. Nothing is sent: "
                + "it is re-encrypted at this session's live keystream position when you Forward.");
        convertStatus.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));
        convertBar.add(convertButton, BorderLayout.WEST);
        convertBar.add(convertStatus, BorderLayout.CENTER);
        convertBar.setVisible(false);

        decodedView.add(pane.uiComponent(), BorderLayout.CENTER);
        decodedView.add(convertBar, BorderLayout.SOUTH);

        cards.add(decodedView, DECODED_VIEW);
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
        List<String> notes = new ArrayList<>(2);
        byte[] edited = draftPanel.editedPlaintext(problem, notes);
        if (!problem.isEmpty()) {
            api.logging().logToError(
                    "Oracle Forms: could not apply an edit, sending the message unchanged: "
                            + problem.get(0));
        }
        if (!notes.isEmpty()) {
            // Never silent: a change the user did not type is a change they have to be told about.
            api.logging().logToOutput("Oracle Forms: adjusted " + String.join(", ", notes)
                    + " to stay inside the text that was edited (they are indices into it, and a "
                    + "caret past the end of its own string is a message no client sends).");
        }

        HttpRequest body = current.request().withBody(ByteArray.byteArray(edited));

        // A converted intercept arrived without markers, so they have to be added here -- this is
        // the only channel by which the handler learns that the body is plaintext, which session's
        // ledger to use, how far to advance the client's leg, and that the edit is authorised.
        return converted ? draft.applyTo(body) : body;
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        this.current = requestResponse;
        this.draft = null;
        this.converted = false;
        this.prepared = null;
        this.interceptTarget = null;
        long mine = generation.incrementAndGet();
        convertBar.setVisible(false);

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
        byte[] body = requestResponse.request().body().getBytes();
        pane.show(target.get(), body);
        offerInterceptEdit(target.get(), body, mine);
    }

    /**
     * Offers to convert a held request into an editable draft, if this is one.
     *
     * <p><strong>Conversion is never automatic.</strong> Returning plaintext from
     * {@link #getRequest} the moment the tab is looked at would rewrite an intercepted request just
     * because the user glanced at it — including a request they meant to forward untouched — and
     * would route it through the intercept branch rather than the ordinary forwarding path. Burp
     * calls {@code setRequestResponse} whenever a tab is shown, so "shown" cannot be allowed to mean
     * "intended". The user presses the button (architecture &sect;6.10 A, &sect;6.12).
     */
    private void offerInterceptEdit(
            FormsDetector.FormsTarget target, byte[] ciphertext, long mine) {

        if (interceptService == null || !editable || !target.isEncrypted()) {
            return;
        }
        this.interceptTarget = target;

        convertButton.setEnabled(false);
        convertStatus.setText("Checking whether this request can be edited\u2026");
        convertBar.setVisible(true);

        interceptService.prepare(target, ciphertext).thenAccept(result -> SwingUtilities.invokeLater(
                () -> {
                    if (generation.get() != mine) {
                        return; // The user has moved on; this answer is for another message.
                    }
                    this.prepared = result;
                    convertButton.setEnabled(result.ok());
                    convertStatus.setText("<html><body style='width: 640px'>"
                            + (result.ok() ? "" : "<b>Cannot edit this request.</b> ")
                            + escape(result.detail()) + "</body></html>");
                }));
    }

    /**
     * Turns the held request into a plaintext draft, on the user's explicit press.
     *
     * <p>Nothing is sent. The tab's contents change — including Burp's own Raw tab, which will now
     * show decoded FHT — and the user still presses Forward.
     */
    private void convertToDraft() {
        if (prepared == null || !prepared.ok() || interceptTarget == null) {
            return;
        }
        this.draft = new DraftMarkers(
                interceptTarget.sessionId(), SendMode.INTERCEPT, interceptTarget.pragma(),
                prepared.originalStreamLength(), prepared.token(), prepared.position());
        this.converted = true;

        showDraft(draft, prepared.plaintext());
        api.logging().logToOutput("Oracle Forms: converted held pragma " + interceptTarget.pragma()
                + " of session " + interceptTarget.sessionId() + " to an editable draft ("
                + prepared.verdict() + "). It is re-encrypted at Forward, not now.");
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
        String modeLine = switch (markers.mode()) {
            case TAIL -> "<b>Append to live session.</b> On Send this is encrypted at the session's "
                    + "current keystream position and the Forms runtime will act on it. This changes "
                    + "the state of a running application session.";
            case INTERCEPT -> "<b>Editing in flight.</b> On <b>Forward</b> this is re-encrypted at "
                    + "this session's live keystream position and sent in place of what the client "
                    + "wrote. Its pragma number and cookies are the client's own and are left alone. "
                    + "The client's session carries on afterwards."
                    + (prepared == null ? "" : "<br>" + escape(prepared.detail()))
                    + "<br><i>If the edit cannot be encrypted it is dropped rather than sent, which "
                    + "will most likely end the session.</i>";
            case OFFSET -> "<b>Original offset — for inspection.</b> On Send this is encrypted at "
                    + "the offset pragma " + markers.originPragma() + " originally occupied. The "
                    + "server will not accept it unless that is still the session's last message.";
        };

        String verb = markers.mode() == SendMode.INTERCEPT ? "Forward" : "Send";
        return "<html><body style='width: 640px'>"
                + "Oracle Forms draft &mdash; session <code>" + escape(markers.sessionId())
                + "</code>, from pragma " + markers.originPragma()
                + ", " + plaintext.length + " plaintext bytes<br>"
                + modeLine
                + (editable
                        ? "<br>Edit a value below \u2014 in the table, or switch to Raw for the "
                                + "bytes \u2014 then " + verb + "."
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
        // A conversion is itself a change to the request: the body becomes plaintext and gains the
        // marker headers. Burp has to be told, or it would forward the ciphertext it already had.
        return converted || (draft != null && draftPanel.isModified());
    }
}
