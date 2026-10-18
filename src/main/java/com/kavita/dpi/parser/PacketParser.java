package com.kavita.dpi.parser;

import com.kavita.dpi.model.ParsedPacket;
import com.kavita.dpi.pcap.RawPacket;

import java.nio.ByteBuffer;
import java.util.Optional;

public final class PacketParser {
    private static final int ETH_HEADER_LEN = 14;
    private static final int ETHERTYPE_IPV4 = 0x0800;
    private static final int PROTO_TCP = 6;
    private static final int PROTO_UDP = 17;

    private PacketParser() {}

    public static Optional<ParsedPacket> parse(RawPacket raw) throws PacketParseException {
        byte[] d = raw.data();
        if (d.length < ETH_HEADER_LEN) {
            throw new PacketParseException("Frame shorter than Ethernet header");
        }
        ByteBuffer buf = ByteBuffer.wrap(d);

        int etherType = buf.getShort(12) & 0xFFFF;
        if (etherType != ETHERTYPE_IPV4) return Optional.empty();

        int ip = ETH_HEADER_LEN;
        if (d.length < ip + 20) throw new PacketParseException("Truncated IPv4 header");

        int versionIhl = d[ip] & 0xFF;
        int version = versionIhl >>> 4;
        int ihlBytes = (versionIhl & 0x0F) * 4;
        if (version != 4) throw new PacketParseException("IP version is " + version);
        if (ihlBytes < 20 || d.length < ip + ihlBytes) {
            throw new PacketParseException("Bad IPv4 header length " + ihlBytes);
        }

        int totalLength = buf.getShort(ip + 2) & 0xFFFF;
        if (totalLength < ihlBytes) throw new PacketParseException("IP total length too small");

        int fragmentOffset = (buf.getShort(ip + 6) & 0xFFFF) & 0x1FFF;
        if (fragmentOffset != 0) return Optional.empty();

        int protocol = d[ip + 9] & 0xFF;
        int srcIp = buf.getInt(ip + 12);
        int dstIp = buf.getInt(ip + 16);

        int ipEnd = Math.min(d.length, ip + totalLength);
        int transport = ip + ihlBytes;

        if (protocol == PROTO_TCP) {
            if (ipEnd < transport + 20) throw new PacketParseException("Truncated TCP header");

            int srcPort = buf.getShort(transport) & 0xFFFF;
            int dstPort = buf.getShort(transport + 2) & 0xFFFF;

            int dataOffset = (d[transport + 12] & 0xFF) >>> 4;
            int tcpLen = dataOffset * 4;
            if (tcpLen < 20 || transport + tcpLen > ipEnd) {
                throw new PacketParseException("Bad TCP header length " + tcpLen);
            }

            int flags = d[transport + 13] & 0xFF;
            int payloadOffset = transport + tcpLen;
            int payloadLength = ipEnd - payloadOffset;

            return Optional.of(new ParsedPacket(srcIp, dstIp, srcPort, dstPort,
                    protocol, flags, payloadOffset, payloadLength));

        } else if (protocol == PROTO_UDP) {
            if (ipEnd < transport + 8) throw new PacketParseException("Truncated UDP header");

            int srcPort = buf.getShort(transport) & 0xFFFF;
            int dstPort = buf.getShort(transport + 2) & 0xFFFF;

            int payloadOffset = transport + 8;
            int payloadLength = ipEnd - payloadOffset;

            return Optional.of(new ParsedPacket(srcIp, dstIp, srcPort, dstPort,
                    protocol, 0, payloadOffset, payloadLength));
        }
        return Optional.empty();
    }
}
