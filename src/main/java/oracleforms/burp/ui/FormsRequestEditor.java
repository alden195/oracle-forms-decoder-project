package oracleforms.burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import java.awt.Component;
import java.util.Optional;
import oracleforms.burp.DecodeService;
import oracleforms.burp.FormsDetector;
import oracleforms.session.Direction;

/**
 * The "Oracle Forms" tab on a request.
 *
 * <p>Read-only for now. Editing waits on {@code FhtWriter} round-tripping captured samples byte for
 * byte — re-encoding a message we cannot yet reproduce exactly would corrupt the session's RC4
 * stream for every message after it (architecture &sect;6).
 */
public final class FormsRequestEditor implements ExtensionProvidedHttpRequestEditor {

    private final FormsEditorPane pane;
    private HttpRequestResponse current;

    public FormsRequestEditor(MontoyaApi api, DecodeService decodeService) {
        this.pane = new FormsEditorPane(api, decodeService, Direction.REQUEST);
    }

    @Override
    public HttpRequest getRequest() {
        // Read-only: hand back exactly what came in.
        return current == null ? null : current.request();
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        this.current = requestResponse;

        Optional<FormsDetector.FormsTarget> target = FormsDetector.detect(
                requestResponse.request(),
                requestResponse.hasResponse() ? requestResponse.response() : null);
        if (target.isEmpty()) {
            pane.showNotApplicable("This request is not an identifiable Oracle Forms message.");
            return;
        }
        pane.show(target.get(), requestResponse.request().body().getBytes());
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
        return pane.uiComponent();
    }

    @Override
    public Selection selectedData() {
        return pane.selectedData();
    }

    @Override
    public boolean isModified() {
        return false;
    }
}
