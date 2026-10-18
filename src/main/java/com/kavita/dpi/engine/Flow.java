package com.kavita.dpi.engine;

import com.kavita.dpi.model.AppType;
import com.kavita.dpi.model.FlowKey;

public final class Flow {
    private final FlowKey key;
    private final int initiatorIp;
    private final int initiatorPort;
    private long packets;
    private long bytes;
    private String hostname;
    private AppType appType = AppType.UNKNOWN;
    private boolean blocked;

    public Flow(FlowKey key, int initiatorIp, int initiatorPort) {
        this.key = key;
        this.initiatorIp = initiatorIp;
        this.initiatorPort = initiatorPort;
    }

    public void addPacket(int frameLength) {
        packets++;
        bytes += frameLength;
    }

    public FlowKey key() { return key; }
    public int initiatorIp() { return initiatorIp; }
    public int initiatorPort() { return initiatorPort; }
    public long packets() { return packets; }
    public long bytes() { return bytes; }
    public String hostname() { return hostname; }
    public void setHostname(String hostname) { this.hostname = hostname; }
    public AppType appType() { return appType; }
    public void setAppType(AppType appType) { this.appType = appType; }
    public boolean blocked() { return blocked; }
    public void setBlocked(boolean blocked) { this.blocked = blocked; }
}
