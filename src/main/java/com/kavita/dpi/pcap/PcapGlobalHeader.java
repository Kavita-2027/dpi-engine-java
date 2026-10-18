package com.kavita.dpi.pcap;

import java.nio.ByteOrder;

public record PcapGlobalHeader(ByteOrder byteOrder, boolean nanosecondTimestamps,
                               int versionMajor, int versionMinor,
                               long snapLen, long linkType) {}