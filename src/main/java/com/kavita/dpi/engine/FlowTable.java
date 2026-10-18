package com.kavita.dpi.engine;

import com.kavita.dpi.model.FlowKey;
import com.kavita.dpi.model.ParsedPacket;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public final class FlowTable {
    private final Map<FlowKey, Flow> flows = new HashMap<>();

    public Flow update(ParsedPacket p, int frameLength) {
        Flow flow = flows.computeIfAbsent(FlowKey.of(p),
                key -> new Flow(key, p.srcIp(), p.srcPort()));
        flow.addPacket(frameLength);
        return flow;
    }

    public int size() { return flows.size(); }
    public Collection<Flow> all() { return flows.values(); }
}
