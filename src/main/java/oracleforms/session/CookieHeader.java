package oracleforms.session;

import java.util.Optional;

/**
 * Minimal reading and rewriting of a {@code Cookie} request header.
 *
 * <p>Exists for one specific job: {@code JSESSIONID_FORMS} rotates every few messages (&sect;3), so a
 * draft taken from a captured message carries a value that may be many rotations stale by the time
 * the user presses Send. A stale value can route the request to a backend that has never heard of the
 * session, which looks exactly like a decryption failure and is not one.
 *
 * <p>{@link #withValue} deliberately rewrites <em>one named cookie in place</em> rather than
 * replacing the header. Anything else the user typed into the Repeater tab is theirs, and silently
 * discarding it would be worse than the problem being solved.
 */
public final class CookieHeader {

    private CookieHeader() {
    }

    /** The value of a named cookie, matched exactly. */
    public static Optional<String> value(String cookieHeader, String name) {
        if (cookieHeader == null || name == null) {
            return Optional.empty();
        }
        for (String part : cookieHeader.split(";")) {
            int eq = part.indexOf('=');
            if (eq < 0) {
                continue;
            }
            if (name.equals(part.substring(0, eq).trim())) {
                String value = part.substring(eq + 1).trim();
                return value.isEmpty() ? Optional.empty() : Optional.of(value);
            }
        }
        return Optional.empty();
    }

    /**
     * Replaces a named cookie's value, preserving the rest of the header and its order.
     *
     * <p>A cookie that is not already present is <em>not</em> added. If the client did not send it,
     * neither should we — inventing one would be a guess about how the deployment is configured.
     */
    public static String withValue(String cookieHeader, String name, String newValue) {
        if (cookieHeader == null || name == null || newValue == null) {
            return cookieHeader;
        }
        String[] parts = cookieHeader.split(";");
        StringBuilder out = new StringBuilder(cookieHeader.length() + newValue.length());
        boolean replaced = false;

        for (int i = 0; i < parts.length; i++) {
            String part = parts[i];
            int eq = part.indexOf('=');
            if (eq >= 0 && name.equals(part.substring(0, eq).trim())) {
                // Keep whatever leading whitespace the original had, so the header still looks the
                // way the client writes it.
                int nameStart = 0;
                while (nameStart < part.length() && Character.isWhitespace(part.charAt(nameStart))) {
                    nameStart++;
                }
                out.append(part, 0, nameStart).append(name).append('=').append(newValue);
                replaced = true;
            } else {
                out.append(part);
            }
            if (i < parts.length - 1) {
                out.append(';');
            }
        }
        return replaced ? out.toString() : cookieHeader;
    }
}
