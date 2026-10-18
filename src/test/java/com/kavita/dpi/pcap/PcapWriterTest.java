package com.kavita.dpi.pcap;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteOrder;

import static org.junit.jupiter.api.Assertions.*;

class PcapWriterTest {

    @Test
    void writtenFileCanBeReadBack() throws Exception {
        PcapGlobalHeader h = new PcapGlobalHeader(ByteOrder.LITTLE_ENDIAN, false, 2, 4, 65535, 1);
        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        try (PcapWriter w = new PcapWriter(sink, h)) {
            w.write(new RawPacket(100, 500, 60, new byte[]{1, 2, 3, 4}));
        }

        PcapReader r = new PcapReader(new ByteArrayInputStream(sink.toByteArray()));
        assertEquals(1, r.header().linkType());
        RawPacket p = r.readNextPacket().orElseThrow();
        assertEquals(100, p.tsSec());
        assertEquals(500, p.tsFraction());
        assertEquals(60, p.originalLength());
        assertArrayEquals(new byte[]{1, 2, 3, 4}, p.data());
        assertTrue(r.readNextPacket().isEmpty());
    }
}
