package com.kavita.dpi.pcap;

import org.junit.jupiter.api.Test;
import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import static org.junit.jupiter.api.Assertions.*;

class PcapReaderTest {

    private static byte[] buildFile(int magic, int inclLen) {
        ByteBuffer b = ByteBuffer.allocate(24 + 16 + 4).order(ByteOrder.LITTLE_ENDIAN);
        b.putInt(magic);
        b.putShort((short) 2); b.putShort((short) 4);
        b.putInt(0); b.putInt(0);
        b.putInt(65535);
        b.putInt(1);
        b.putInt(100); b.putInt(500);
        b.putInt(inclLen); b.putInt(4);
        b.put(new byte[]{1, 2, 3, 4});
        return b.array();
    }

    @Test
    void readsHeaderAndOnePacket() throws Exception {
        byte[] bytes = buildFile(0xa1b2c3d4, 4);
        PcapReader reader = new PcapReader(new ByteArrayInputStream(bytes));
        assertEquals(1, reader.header().linkType());
        assertEquals(65535, reader.header().snapLen());

        RawPacket p = reader.readNextPacket().orElseThrow();
        assertEquals(100, p.tsSec());
        assertArrayEquals(new byte[]{1, 2, 3, 4}, p.data());

        assertTrue(reader.readNextPacket().isEmpty());
    }

    @Test
    void rejectsBadMagicNumber() {
        byte[] bytes = buildFile(0x12345678, 4);
        assertThrows(PcapFormatException.class,
                () -> new PcapReader(new ByteArrayInputStream(bytes)));
    }

    @Test
    void rejectsTruncatedPackets() throws Exception{
        byte[] bytes = buildFile(0xa1b2c3d4, 100);
        PcapReader reader = new PcapReader(new ByteArrayInputStream(bytes));
        assertThrows(PcapFormatException.class, () -> reader.readNextPacket());
    }
}
