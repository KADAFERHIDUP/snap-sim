package id.my.kadaferhidup.snapsim.json;

import java.lang.reflect.RecordComponent;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * A small JSON writer and reader, enough for this API: objects, arrays, strings, numbers,
 * booleans and null. Records are written by their components in snake_case, {@link Instant}
 * as ISO-8601 and enums by name.
 */
public final class Json {

    private Json() {
    }

    // ------------------------------------------------------------------ write

    public static String write(Object value) {
        StringBuilder sb = new StringBuilder();
        write(value, sb);
        return sb.toString();
    }

    private static void write(Object v, StringBuilder sb) {
        if (v == null) {
            sb.append("null");
        } else if (v instanceof String s) {
            quote(s, sb);
        } else if (v instanceof Boolean || v instanceof Integer || v instanceof Long || v instanceof Short) {
            sb.append(v);
        } else if (v instanceof Number n) {
            double d = n.doubleValue();
            if (Double.isNaN(d) || Double.isInfinite(d)) {
                throw new IllegalArgumentException("JSON tidak bisa memuat " + d);
            }
            sb.append(n);
        } else if (v instanceof Enum<?> e) {
            quote(e.name(), sb);
        } else if (v instanceof Instant i) {
            quote(i.toString(), sb);
        } else if (v instanceof Optional<?> o) {
            write(o.orElse(null), sb);
        } else if (v instanceof Map<?, ?> m) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : m.entrySet()) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                quote(String.valueOf(e.getKey()), sb);
                sb.append(':');
                write(e.getValue(), sb);
            }
            sb.append('}');
        } else if (v instanceof Collection<?> c) {
            sb.append('[');
            boolean first = true;
            for (Object o : c) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                write(o, sb);
            }
            sb.append(']');
        } else if (v.getClass().isRecord()) {
            Map<String, Object> m = new LinkedHashMap<>();
            for (RecordComponent rc : v.getClass().getRecordComponents()) {
                try {
                    m.put(snake(rc.getName()), rc.getAccessor().invoke(v));
                } catch (ReflectiveOperationException e) {
                    throw new IllegalStateException(e);
                }
            }
            write(m, sb);
        } else {
            throw new IllegalArgumentException("Tipe tidak didukung: " + v.getClass().getName());
        }
    }

    static String snake(String camel) {
        StringBuilder sb = new StringBuilder();
        for (char c : camel.toCharArray()) {
            if (Character.isUpperCase(c)) {
                sb.append('_').append(Character.toLowerCase(c));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private static void quote(String s, StringBuilder sb) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '<' -> sb.append("\\u003c");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
    }

    // ------------------------------------------------------------------ read

    /** Parses JSON text. Objects become {@code Map<String,Object>}, numbers {@code Long} or {@code Double}. */
    public static Object parse(String text) {
        Reader r = new Reader(text);
        r.ws();
        Object v = r.value(0);
        r.ws();
        if (r.pos != text.length()) {
            throw r.error("Ada teks setelah JSON selesai");
        }
        return v;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseObject(String text) {
        Object v = parse(text == null || text.isBlank() ? "{}" : text);
        if (!(v instanceof Map)) {
            throw new JsonException("Body harus objek JSON");
        }
        return (Map<String, Object>) v;
    }

    /** Thrown for text that is not valid JSON. */
    public static final class JsonException extends RuntimeException {

        private static final long serialVersionUID = 1L;

        public JsonException(String message) {
            super(message);
        }
    }

    private static final class Reader {
        private static final int MAX_DEPTH = 32;
        private final String s;
        private int pos;

        Reader(String s) {
            this.s = s;
        }

        JsonException error(String msg) {
            return new JsonException(msg + " (posisi " + pos + ")");
        }

        void ws() {
            while (pos < s.length() && Character.isWhitespace(s.charAt(pos))) {
                pos++;
            }
        }

        char peek() {
            if (pos >= s.length()) {
                throw error("JSON terpotong");
            }
            return s.charAt(pos);
        }

        Object value(int depth) {
            if (depth > MAX_DEPTH) {
                throw error("JSON terlalu dalam");
            }
            char c = peek();
            return switch (c) {
                case '{' -> object(depth);
                case '[' -> array(depth);
                case '"' -> string();
                case 't' -> literal("true", Boolean.TRUE);
                case 'f' -> literal("false", Boolean.FALSE);
                case 'n' -> literal("null", null);
                default -> number();
            };
        }

        Object literal(String word, Object v) {
            if (!s.startsWith(word, pos)) {
                throw error("Nilai tidak dikenal");
            }
            pos += word.length();
            return v;
        }

        Map<String, Object> object(int depth) {
            Map<String, Object> m = new LinkedHashMap<>();
            pos++;
            ws();
            if (peek() == '}') {
                pos++;
                return m;
            }
            while (true) {
                ws();
                if (peek() != '"') {
                    throw error("Kunci objek harus string");
                }
                String k = string();
                ws();
                if (peek() != ':') {
                    throw error("Butuh ':'");
                }
                pos++;
                ws();
                m.put(k, value(depth + 1));
                ws();
                char c = peek();
                pos++;
                if (c == '}') {
                    return m;
                }
                if (c != ',') {
                    throw error("Butuh ',' atau '}'");
                }
            }
        }

        List<Object> array(int depth) {
            List<Object> l = new ArrayList<>();
            pos++;
            ws();
            if (peek() == ']') {
                pos++;
                return l;
            }
            while (true) {
                ws();
                l.add(value(depth + 1));
                ws();
                char c = peek();
                pos++;
                if (c == ']') {
                    return l;
                }
                if (c != ',') {
                    throw error("Butuh ',' atau ']'");
                }
            }
        }

        String string() {
            StringBuilder sb = new StringBuilder();
            pos++;
            while (true) {
                char c = peek();
                pos++;
                if (c == '"') {
                    return sb.toString();
                }
                if (c == '\\') {
                    char e = peek();
                    pos++;
                    switch (e) {
                        case '"', '\\', '/' -> sb.append(e);
                        case 'n' -> sb.append('\n');
                        case 'r' -> sb.append('\r');
                        case 't' -> sb.append('\t');
                        case 'b' -> sb.append('\b');
                        case 'f' -> sb.append('\f');
                        case 'u' -> {
                            if (pos + 4 > s.length()) {
                                throw error("Escape \\u terpotong");
                            }
                            try {
                                sb.append((char) Integer.parseInt(s.substring(pos, pos + 4), 16));
                            } catch (NumberFormatException ex) {
                                throw error("Escape \\u tidak valid");
                            }
                            pos += 4;
                        }
                        default -> throw error("Escape tidak dikenal");
                    }
                } else if (c < 0x20) {
                    throw error("Karakter kontrol di dalam string");
                } else {
                    sb.append(c);
                }
            }
        }

        Number number() {
            int start = pos;
            if (pos < s.length() && s.charAt(pos) == '-') {
                pos++;
            }
            boolean fraction = false;
            while (pos < s.length()) {
                char c = s.charAt(pos);
                if (c >= '0' && c <= '9') {
                    pos++;
                } else if (c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') {
                    fraction = true;
                    pos++;
                } else {
                    break;
                }
            }
            String n = s.substring(start, pos);
            if (n.isEmpty() || n.equals("-")) {
                throw error("Nilai tidak dikenal");
            }
            try {
                return fraction ? (Number) Double.parseDouble(n) : (Number) Long.parseLong(n);
            } catch (NumberFormatException e) {
                throw error("Angka tidak valid: " + n);
            }
        }
    }
}
