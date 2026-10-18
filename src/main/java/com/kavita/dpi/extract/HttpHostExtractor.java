package com.kavita.dpi.extract;

import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Optional;

public final class HttpHostExtractor {
    private static final String[] METHODS =
            {"GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH "};

    private HttpHostExtractor() {}

    public static Optional<String> extract(byte[] d, int off, int len) {
        String text = new String(d, off, Math.min(len, 2048), StandardCharsets.ISO_8859_1);

        boolean isRequest = false;
        for (String m : METHODS) {
            if (text.startsWith(m)) { isRequest = true; break; }
        }
        if (!isRequest) return Optional.empty();

        for (String line : text.split("\r\n")) {
            if (line.regionMatches(true, 0, "host:", 0, 5)) {
                String host = line.substring(5).trim();
                if (!host.startsWith("[")) {                            // skip IPv6 literals
                    int colon = host.indexOf(':');
                    if (colon >= 0) host = host.substring(0, colon);    // drop the port
                }
                if (host.isEmpty()) return Optional.empty();
                return Optional.of(host.toLowerCase(Locale.ROOT));
            }
        }
        return Optional.empty();
    }
}
