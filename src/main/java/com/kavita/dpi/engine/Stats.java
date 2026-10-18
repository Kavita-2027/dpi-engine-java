package com.kavita.dpi.engine;

import com.kavita.dpi.model.AppType;

import java.util.EnumMap;
import java.util.Map;

public final class Stats {
    long total, bytes, tcp, udp, other, malformed, forwarded, dropped;
    final Map<AppType, Long> appPackets = new EnumMap<>(AppType.class);

    void countApp(AppType app) {
        appPackets.merge(app, 1L, Long::sum);
    }

    public void merge(Stats o) {
        total += o.total;
        bytes += o.bytes;
        tcp += o.tcp;
        udp += o.udp;
        other += o.other;
        malformed += o.malformed;
        forwarded += o.forwarded;
        dropped += o.dropped;
        o.appPackets.forEach((app, n) -> appPackets.merge(app, n, Long::sum));
    }

    public long total() { return total; }
    public long forwarded() { return forwarded; }
    public long dropped() { return dropped; }
    public long malformed() { return malformed; }
    public long other() { return other; }
}
