package com.kavita.dpi.pcap;

import java.io.BufferedOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;

public final class PcapWriter implements Closeable {
    private final OutputStream out;

    public PcapWriter(OutputStream sink, PcapGlobalHeader h) throws IOException {
        this.out = new BufferedOutputStream(sink);
        ByteBuffer b = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        b.putInt(h.nanosecondTimestamps() ? 0xa1b23c4d : 0xa1b2c3d4);
        b.putShort((short) h.versionMajor());
        b.putShort((short) h.versionMinor());
        b.putInt(0);
        b.putInt(0);
        b.putInt((int) h.snapLen());
        b.putInt((int) h.linkType());
        out.write(b.array());
    }

    public static PcapWriter create(Path file, PcapGlobalHeader h) throws IOException {
        return new PcapWriter(Files.newOutputStream(file), h);
    }

    public void write(RawPacket p) throws IOException {
        ByteBuffer b = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        b.putInt((int) p.tsSec());
        b.putInt((int) p.tsFraction());
        b.putInt(p.data().length);
        b.putInt((int) p.originalLength());
        out.write(b.array());
        out.write(p.data());
    }

    @Override
    public void close() throws IOException {
        out.close();
    }
}
