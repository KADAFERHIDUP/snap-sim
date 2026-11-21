package id.my.kadaferhidup.snapsim.http;

import com.sun.net.httpserver.HttpExchange;

final class Http {

    private Http() {
    }

    /**
     * Behind a reverse proxy the connection comes from the proxy, which appends the real client to
     * X-Forwarded-For. Anything before that last entry was written by the client and can be forged.
     */
    static String clientIp(HttpExchange ex) {
        String xff = ex.getRequestHeaders().getFirst("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            String[] parts = xff.split(",");
            String last = parts[parts.length - 1].strip();
            if (!last.isEmpty() && last.length() <= 45) {
                return last;
            }
        }
        return ex.getRemoteAddress().getAddress().getHostAddress();
    }
}
