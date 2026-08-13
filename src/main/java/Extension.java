import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import oracleforms.burp.OracleFormsDecoder;

/**
 * Entry point.
 *
 * <p>Burp requires the extension class to be locatable from the jar's root, so this stays a thin
 * shell in the default package. Everything real lives in {@link OracleFormsDecoder}.
 */
public class Extension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        new OracleFormsDecoder().initialize(montoyaApi);
    }
}
