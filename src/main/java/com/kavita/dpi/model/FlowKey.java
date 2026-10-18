package com.kavita.dpi.model;

public record FlowKey(int ipA, int portA, int ipB, int portB, int protocol) {

    public static FlowKey of(ParsedPacket p) {
        if (compareEndpoints(p.srcIp(), p.srcPort(), p.dstIp(), p.dstPort()) <= 0) {
            return new FlowKey(p.srcIp(), p.srcPort(), p.dstIp(), p.dstPort(), p.protocol());
        }
        return new FlowKey(p.dstIp(), p.dstPort(), p.srcIp(), p.srcPort(), p.protocol());
    }

    private static int compareEndpoints(int ip1, int port1, int ip2, int port2) {
        int c = Integer.compare(ip1, ip2);
        return c != 0 ? c : Integer.compare(port1, port2);
    }
}
