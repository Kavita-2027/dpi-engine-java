package com.kavita.dpi.concurrent;

import com.kavita.dpi.model.ParsedPacket;
import com.kavita.dpi.pcap.RawPacket;

public record Task(Task.Kind kind, long seq, int hash, RawPacket raw, ParsedPacket parsed) {
    public enum Kind { PARSED, UNSUPPORTED, MALFORMED, POISON }

    public static Task poison() {
        return new Task(Kind.POISON, -1, 0, null, null);
    }
}
