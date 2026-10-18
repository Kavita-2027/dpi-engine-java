package com.kavita.dpi.concurrent;

import com.kavita.dpi.pcap.RawPacket;

public record Result(long seq, RawPacket raw, boolean forward, boolean done) {
    public static Result finished() {
        return new Result(-1, null, false, true);
    }
}