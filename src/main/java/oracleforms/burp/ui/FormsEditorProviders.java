package oracleforms.burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;
import oracleforms.burp.DecodeService;

/**
 * Hands Burp a fresh editor for each place one is needed.
 *
 * <p>Burp asks for an editor per view, not per message, so these are cheap constructors; the
 * expensive state (checkpoints, history indexes, decoded text) lives in the shared
 * {@link DecodeService} rather than in the editors, which are created and discarded freely.
 */
public final class FormsEditorProviders {

    private FormsEditorProviders() {
    }

    public static HttpRequestEditorProvider requestProvider(
            MontoyaApi api, DecodeService decodeService,
            oracleforms.burp.proxy.InterceptEditService interceptService) {

        return new HttpRequestEditorProvider() {
            @Override
            public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(
                    EditorCreationContext context) {
                // Burp creates proxy-history editors READ_ONLY, so gating on this keeps history
                // read-only for free and puts the editable path only where an edit can mean
                // something -- a Repeater tab (architecture §6.6).
                boolean editable = context.editorMode() != EditorMode.READ_ONLY;

                // Mode D is offered only on a request the Proxy is holding. Offering it in Repeater
                // would be wrong rather than merely useless: an in-flight edit advances the
                // *client's* keystream leg past a message the client is waiting to have forwarded,
                // and in Repeater there is no such message (architecture §6.12).
                return new FormsRequestEditor(api, decodeService, editable,
                        editable && isProxy(context) ? interceptService : null);
            }
        };
    }

    /**
     * Whether this editor belongs to a request the Proxy is holding.
     *
     * <p>Fails closed on purpose. {@code toolSource()} is confirmed to exist on
     * {@link EditorCreationContext}, but what it reports for the Intercept tab is an assumption this
     * design records rather than one it has verified. If it cannot be read, or names another tool,
     * no conversion bar appears — the tab still decodes read-only, which is exactly what it did
     * before Mode D existed. A wrong "yes" would offer an in-flight edit somewhere nothing is in
     * flight; a wrong "no" costs a button.
     */
    private static boolean isProxy(EditorCreationContext context) {
        try {
            return context.toolSource() != null
                    && context.toolSource().isFromTool(ToolType.PROXY);
        } catch (RuntimeException e) {
            return false;
        }
    }

    public static HttpResponseEditorProvider responseProvider(
            MontoyaApi api, DecodeService decodeService) {
        return new HttpResponseEditorProvider() {
            @Override
            public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(
                    EditorCreationContext context) {
                return new FormsResponseEditor(api, decodeService);
            }
        };
    }
}
