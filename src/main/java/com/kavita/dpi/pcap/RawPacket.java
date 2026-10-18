package com.kavita.dpi.pcap;

public record RawPacket(long tsSec, long tsFraction, long originalLength, byte[] data) {}
