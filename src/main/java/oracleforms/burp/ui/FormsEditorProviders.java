package oracleforms.burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
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
            MontoyaApi api, DecodeService decodeService) {
        return new HttpRequestEditorProvider() {
            @Override
            public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(
                    EditorCreationContext context) {
                return new FormsRequestEditor(api, decodeService);
            }
        };
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
