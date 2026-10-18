package com.kavita.dpi.extract;

import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Optional;

public final class SniExtractor {
    private SniExtractor() {}

    public static Optional<String> extract(byte[] d, int off, int len) {
        int end = off + len;
        if (len < 9) return Optional.empty();
        if ((d[off] & 0xFF) != 0x16) return Optional.empty();           // not a handshake record

        int version = u16(d, off + 1);
        if (version < 0x0300 || version > 0x0304) return Optional.empty();

        int recordLen = u16(d, off + 3);
        if (recordLen > len - 5) return Optional.empty();               // split across segments: unsupported
        if ((d[off + 5] & 0xFF) != 0x01) return Optional.empty();       // not a ClientHello

        int pos = off + 43;                                             // skip headers, version, random

        if (pos + 1 > end) return Optional.empty();
        pos += 1 + (d[pos] & 0xFF);                                     // session ID

        if (pos + 2 > end) return Optional.empty();
        pos += 2 + u16(d, pos);                                         // cipher suites

        if (pos + 1 > end) return Optional.empty();
        pos += 1 + (d[pos] & 0xFF);                                     // compression methods

        if (pos + 2 > end) return Optional.empty();
        int extLen = u16(d, pos);
        pos += 2;
        int extEnd = Math.min(pos + extLen, end);

        while (pos + 4 <= extEnd) {
            int type = u16(d, pos);
            int l = u16(d, pos + 2);
            pos += 4;
            if (pos + l > extEnd) return Optional.empty();

            if (type == 0x0000) {                                       // server_name
                if (l < 5) return Optional.empty();
                int nameType = d[pos + 2] & 0xFF;
                int nameLen = u16(d, pos + 3);
                if (nameType != 0 || nameLen > l - 5) return Optional.empty();
                String host = new String(d, pos + 5, nameLen, StandardCharsets.US_ASCII);
                return Optional.of(host.toLowerCase(Locale.ROOT));
            }
            pos += l;
        }
        return Optional.empty();
    }

    private static int u16(byte[] d, int i) {
        return ((d[i] & 0xFF) << 8) | (d[i + 1] & 0xFF);
    }
}