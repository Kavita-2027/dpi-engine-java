package com.kavita.dpi.pcap;

import java.io.IOException;

public class PcapFormatException extends IOException {
    public PcapFormatException(String message) {
        super(message);
    }
}
