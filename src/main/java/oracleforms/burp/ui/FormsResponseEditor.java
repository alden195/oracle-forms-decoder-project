package oracleforms.burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import java.awt.Component;
import java.util.Optional;
import oracleforms.burp.DecodeService;
import oracleforms.burp.FormsDetector;
import oracleforms.session.Direction;

/**
 * The "Oracle Forms" tab on a response.
 *
 * <p>The session and pragma come from the <em>initiating request</em>: responses carry no
 * {@code Pragma} header and no {@code Cookie}, and a request/response pair shares one sequence
 * number. The body itself belongs to the response direction's own RC4 stream.
 */
public final class FormsResponseEditor implements ExtensionProvidedHttpResponseEditor {

    private final FormsEditorPane pane;
    private HttpRequestResponse current;

    public FormsResponseEditor(MontoyaApi api, DecodeService decodeService) {
        this.pane = new FormsEditorPane(api, decodeService, Direction.RESPONSE);
    }

    @Override
    public HttpResponse getResponse() {
        return current == null ? null : current.response();
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        this.current = requestResponse;

        if (!requestResponse.hasResponse()) {
            pane.showNotApplicable("This message has no response body to decode.");
            return;
        }
        Optional<FormsDetector.FormsTarget> target =
                FormsDetector.detect(requestResponse.request(), requestResponse.response());
        if (target.isEmpty()) {
            pane.showNotApplicable("This response is not an identifiable Oracle Forms message.");
            return;
        }
        pane.show(target.get(), requestResponse.response().body().getBytes());
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        try {
            return requestResponse != null
                    && requestResponse.hasResponse()
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
