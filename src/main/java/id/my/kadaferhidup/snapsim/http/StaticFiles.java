package id.my.kadaferhidup.snapsim.http;

import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

/** Serves the web console from the classpath folder {@code web/}. Only plain file names, no traversal. */
final class StaticFiles {

    private static final Map<String, String> TYPES = Map.of(
            "html", "text/html; charset=utf-8",
            "css", "text/css; charset=utf-8",
            "js", "text/javascript; charset=utf-8",
            "svg", "image/svg+xml",
            "png", "image/png");

    void serve(HttpExchange ex, String path) throws IOException {
        String p = path.equals("/") ? "/index.html" : path;
        String ext = p.substring(p.lastIndexOf('.') + 1);
        String type = TYPES.get(ext);
        byte[] b = null;
        if (type != null && p.matches("^/[a-zA-Z0-9_-]+\\.[a-z]+$")) {
            try (InputStream in = StaticFiles.class.getResourceAsStream("/web" + p)) {
                b = in == null ? null : in.readAllBytes();
            }
        }
        if (b == null) {
            Api.json(ex, 404, Map.of("responseCode", "4040000", "responseMessage", "Not Found"));
            return;
        }
        ex.getResponseHeaders().set("Content-Type", type);
        ex.getResponseHeaders().set("Cache-Control", p.equals("/index.html") ? "no-cache" : "public, max-age=600");
        boolean head = ex.getRequestMethod().equals("HEAD");
        ex.sendResponseHeaders(200, head ? -1 : b.length);
        if (!head) {
            ex.getResponseBody().write(b);
        }
    }
}
