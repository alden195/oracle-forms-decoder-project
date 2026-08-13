package oracleforms.session;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Serializes the key store to and from JSON, for moving keys between projects.
 *
 * <p>Hand-rolled rather than pulled from a library, because BApp criterion 4 wants every dependency
 * bundled and a JSON library is a lot of jar for one flat array of strings.
 *
 * <p>The reader is deliberately narrow: it accepts an array of objects whose values are all strings
 * or numbers, and ignores anything else. It is not a general JSON parser and does not try to be —
 * import files are user-supplied, so the parser is bounded, non-recursive, and cannot be steered
 * into deep nesting or huge allocations.
 */
public final class KeyStoreJson {

    /** Refuse pathological inputs outright rather than trying to parse them. */
    private static final int MAX_INPUT_CHARS = 4 * 1024 * 1024;

    private KeyStoreJson() {
    }

    public static String export(List<SessionKey> keys) {
        StringBuilder out = new StringBuilder(256 + keys.size() * 200);
        out.append("[\n");
        for (int i = 0; i < keys.size(); i++) {
            SessionKey key = keys.get(i);
            out.append("  {\n");
            field(out, "sessionId", key.sessionId(), true);
            field(out, "key", key.keyHex(), true);
            field(out, "host", key.host(), true);
            field(out, "firstSeen", Long.toString(key.firstSeen()), true);
            field(out, "lastSeen", Long.toString(key.lastSeen()), true);
            field(out, "label", key.label(), true);
            field(out, "source", key.source().wireName(), false);
            out.append("  }").append(i < keys.size() - 1 ? "," : "").append('\n');
        }
        out.append("]\n");
        return out.toString();
    }

    private static void field(StringBuilder out, String name, String value, boolean comma) {
        out.append("    \"").append(name).append("\": \"").append(escape(value)).append('"')
                .append(comma ? "," : "").append('\n');
    }

    private static String escape(String value) {
        StringBuilder out = new StringBuilder(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        return out.toString();
    }

    /**
     * Parses an exported file.
     *
     * <p>Entries that are malformed — a bad key length, a missing session id — are skipped rather
     * than aborting the whole import, and reported through {@code problems} so the user is told what
     * was dropped instead of silently getting fewer keys than the file contained.
     *
     * @param problems collects one message per rejected entry; may be null
     */
    public static List<SessionKey> importFrom(String json, List<String> problems) {
        List<SessionKey> out = new ArrayList<>();
        if (json == null || json.length() > MAX_INPUT_CHARS) {
            addProblem(problems, "input is empty or too large to parse");
            return out;
        }

        for (Map<String, String> object : objects(json)) {
            try {
                String sessionId = object.get("sessionId");
                String keyHex = object.get("key");
                if (sessionId == null || keyHex == null) {
                    addProblem(problems, "entry without a sessionId or key, skipped");
                    continue;
                }
                out.add(new SessionKey(
                        sessionId,
                        SessionKey.parseKeyHex(keyHex),
                        object.getOrDefault("host", ""),
                        parseLong(object.get("firstSeen")),
                        parseLong(object.get("lastSeen")),
                        object.getOrDefault("label", ""),
                        KeySource.fromWireName(object.getOrDefault("source",
                                KeySource.IMPORTED.wireName()))));
            } catch (RuntimeException e) {
                addProblem(problems, "entry for session "
                        + object.getOrDefault("sessionId", "?") + " skipped: " + e.getMessage());
            }
        }
        return out;
    }

    /**
     * Splits the input into flat name/value maps.
     *
     * <p>A single forward pass with no recursion: it tracks whether it is inside a string, collects
     * {@code "name": "value"} pairs, and starts a new object at each {@code &#123;}. Nested objects
     * and arrays are not part of the schema and are not supported.
     */
    static List<Map<String, String>> objects(String json) {
        List<Map<String, String>> objects = new ArrayList<>();
        Map<String, String> current = null;
        String pendingName = null;
        StringBuilder token = new StringBuilder();
        boolean inString = false;
        boolean escaped = false;
        boolean sawColon = false;

        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);

            if (inString) {
                if (escaped) {
                    token.append(unescape(c, json, i));
                    if (c == 'u') {
                        i += 4;
                    }
                    escaped = false;
                } else if (c == '\\') {
                    escaped = true;
                } else if (c == '"') {
                    inString = false;
                    if (current != null) {
                        if (!sawColon) {
                            pendingName = token.toString();
                        } else {
                            current.put(pendingName, token.toString());
                            pendingName = null;
                            sawColon = false;
                        }
                    }
                    token.setLength(0);
                } else {
                    token.append(c);
                }
                continue;
            }

            switch (c) {
                case '"' -> inString = true;
                case '{' -> {
                    current = new LinkedHashMap<>();
                    pendingName = null;
                    sawColon = false;
                }
                case '}' -> {
                    if (current != null) {
                        // A bare number value still pending, e.g. "firstSeen": 123
                        flushBareValue(current, pendingName, token);
                        objects.add(current);
                        current = null;
                    }
                    pendingName = null;
                    sawColon = false;
                    token.setLength(0);
                }
                case ':' -> sawColon = true;
                case ',' -> {
                    if (current != null) {
                        flushBareValue(current, pendingName, token);
                    }
                    pendingName = null;
                    sawColon = false;
                    token.setLength(0);
                }
                default -> {
                    if (sawColon && !Character.isWhitespace(c)) {
                        token.append(c);
                    }
                }
            }
        }
        return objects;
    }

    /** Stores an unquoted value (a number or literal) collected since the colon. */
    private static void flushBareValue(
            Map<String, String> current, String pendingName, StringBuilder token) {
        if (pendingName != null && token.length() > 0) {
            current.put(pendingName, token.toString().trim());
        }
    }

    private static char unescape(char c, String json, int i) {
        return switch (c) {
            case 'n' -> '\n';
            case 'r' -> '\r';
            case 't' -> '\t';
            case 'b' -> '\b';
            case 'f' -> '\f';
            case 'u' -> parseUnicode(json, i);
            default -> c; // covers \" and \\ and anything unexpected
        };
    }

    private static char parseUnicode(String json, int i) {
        if (i + 4 < json.length()) {
            try {
                return (char) Integer.parseInt(json.substring(i + 1, i + 5), 16);
            } catch (NumberFormatException e) {
                return '?';
            }
        }
        return '?';
    }

    private static long parseLong(String value) {
        try {
            return value == null ? 0L : Long.parseLong(value.trim());
        } catch (NumberFormatException e) {
            return 0L;
        }
    }

    private static void addProblem(List<String> problems, String message) {
        if (problems != null) {
            problems.add(message);
        }
    }
}
