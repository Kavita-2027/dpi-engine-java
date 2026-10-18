package com.kavita.dpi.model;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class FlowKeyTest {

    private static ParsedPacket pkt(int srcIp, int srcPort, int dstIp, int dstPort) {
        return new ParsedPacket(srcIp, dstIp, srcPort, dstPort, 6, 0, 0, 0);
    }

    @Test
    void requestAndReplyShareOneKey() {
        ParsedPacket request = pkt(0xC0A80164, 54321, 0x8EFAB9CE, 443);
        ParsedPacket reply   = pkt(0x8EFAB9CE, 443, 0xC0A80164, 54321);
        assertEquals(FlowKey.of(request), FlowKey.of(reply));
    }

    @Test
    void differentPortsAreDifferentFlows() {
        ParsedPacket a = pkt(0xC0A80164, 54321, 0x8EFAB9CE, 443);
        ParsedPacket b = pkt(0xC0A80164, 54322, 0x8EFAB9CE, 443);
        assertNotEquals(FlowKey.of(a), FlowKey.of(b));
    }
}
