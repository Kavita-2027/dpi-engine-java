package com.kavita.dpi.model;

public record ParsedPacket(int srcIp, int dstIp, int srcPort, int dstPort,
                           int protocol, int tcpFlags,
                           int payloadOffset, int payloadLength) {

    public static String ipToString(int ip) {
        return ((ip >>> 24) & 0xFF) + "." + ((ip >>> 16) & 0xFF) + "."
                + ((ip >>> 8) & 0xFF) + "." + (ip & 0xFF);
    }
}
