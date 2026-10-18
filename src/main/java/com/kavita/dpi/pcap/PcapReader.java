package com.kavita.dpi.pcap;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

public final class PcapReader implements Closeable {
    private static final int GLOBAL_HEADER_LEN = 24;
    private static final int RECORD_HEADER_LEN = 16;
    private static final int MAX_PACKET_LEN = 262_144;
    private static final int MAGIC_MICRO = 0xa1b2c3d4;
    private static final int MAGIC_NANO  = 0xa1b23c4d;

    private final InputStream in;
    private final PcapGlobalHeader header;

    public PcapReader(InputStream source) throws IOException {
        this.in = new BufferedInputStream(source);
        byte[] raw = in.readNBytes(GLOBAL_HEADER_LEN);
        if (raw.length < GLOBAL_HEADER_LEN) {
            throw new PcapFormatException("File too short for a PCAP header");
        }
        ByteBuffer buf = ByteBuffer.wrap(raw);
        int magic = buf.getInt();
        ByteOrder order;
        boolean nano;
        if (magic == MAGIC_MICRO)                            { order = ByteOrder.BIG_ENDIAN;    nano = false; }
        else if (magic == MAGIC_NANO)                        { order = ByteOrder.BIG_ENDIAN;    nano = true;  }
        else if (Integer.reverseBytes(magic) == MAGIC_MICRO) { order = ByteOrder.LITTLE_ENDIAN; nano = false; }
        else if (Integer.reverseBytes(magic) == MAGIC_NANO)  { order = ByteOrder.LITTLE_ENDIAN; nano = true;  }
        else throw new PcapFormatException(
                    "Not a PCAP file (magic 0x" + Integer.toHexString(magic) + ")");

        buf.order(order);
        int major = buf.getShort() & 0xFFFF;
        int minor = buf.getShort() & 0xFFFF;
        buf.getInt();
        buf.getInt();
        long snapLen = Integer.toUnsignedLong(buf.getInt());
        long linkType = Integer.toUnsignedLong(buf.getInt());
        this.header = new PcapGlobalHeader(order, nano, major, minor, snapLen, linkType);
    }
    public static PcapReader open(Path file) throws IOException {
        return new PcapReader(Files.newInputStream(file));
    }

    public PcapGlobalHeader header() { return header; }

    public Optional<RawPacket> readNextPacket() throws IOException {
        byte[] rec = in.readNBytes(RECORD_HEADER_LEN);
        if (rec.length == 0) return Optional.empty();
        if (rec.length < RECORD_HEADER_LEN) {
            throw new PcapFormatException("Truncated packet record header");
        }
        ByteBuffer buf = ByteBuffer.wrap(rec).order(header.byteOrder());
        long tsSec   = Integer.toUnsignedLong(buf.getInt());
        long tsFrac  = Integer.toUnsignedLong(buf.getInt());
        long inclLen = Integer.toUnsignedLong(buf.getInt());
        long origLen = Integer.toUnsignedLong(buf.getInt());
        if (inclLen > MAX_PACKET_LEN) {
            throw new PcapFormatException("Implausible packet length: " + inclLen);
        }
        byte[] data = in.readNBytes((int) inclLen);
        if (data.length < inclLen) {
            throw new PcapFormatException("Truncated packet data");
        }
        return Optional.of(new RawPacket(tsSec, tsFrac, origLen, data));
    }

    @Override
    public void close() throws IOException { in.close(); }
}