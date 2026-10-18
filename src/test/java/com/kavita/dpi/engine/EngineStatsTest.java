package com.kavita.dpi.engine;

import com.kavita.dpi.model.AppType;
import com.kavita.dpi.pcap.RawPacket;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class EngineStatsTest {

    @Test
    void mergeAddsCounters() {
        Stats a = new Stats();
        a.total = 2; a.dropped = 1; a.countApp(AppType.HTTPS);
        Stats b = new Stats();
        b.total = 3; b.dropped = 2; b.countApp(AppType.HTTPS); b.countApp(AppType.DNS);

        a.merge(b);

        assertEquals(5, a.total());
        assertEquals(3, a.dropped());
        assertEquals(2L, a.appPackets.get(AppType.HTTPS));
        assertEquals(1L, a.appPackets.get(AppType.DNS));
    }

    @Test
    void malformedPacketIsDroppedAndCounted() {
        DpiEngine engine = new DpiEngine(new RuleSet());
        DpiEngine.Verdict v = engine.process(new RawPacket(0, 0, 5, new byte[5]));
        assertEquals(DpiEngine.Verdict.DROP, v);
        assertEquals(1, engine.stats().malformed());
        assertEquals(1, engine.stats().total());
    }
}
