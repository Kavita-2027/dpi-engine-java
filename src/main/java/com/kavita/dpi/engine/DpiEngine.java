package com.kavita.dpi.engine;

import com.kavita.dpi.extract.HttpHostExtractor;
import com.kavita.dpi.extract.SniExtractor;
import com.kavita.dpi.model.AppType;
import com.kavita.dpi.model.ParsedPacket;
import com.kavita.dpi.parser.PacketParseException;
import com.kavita.dpi.parser.PacketParser;
import com.kavita.dpi.pcap.RawPacket;

import java.util.Collection;
import java.util.Optional;

public final class DpiEngine {
    public enum Verdict { FORWARD, DROP }

    private final RuleSet rules;
    private final FlowTable flows = new FlowTable();
    private final Stats stats = new Stats();

    public DpiEngine(RuleSet rules) { this.rules = rules; }

    /** Single-threaded convenience: parse, then process. */
    public Verdict process(RawPacket raw) {
        try {
            Optional<ParsedPacket> parsed = PacketParser.parse(raw);
            if (parsed.isEmpty()) return recordUnsupported(raw);
            return processParsed(raw, parsed.get());
        } catch (PacketParseException e) {
            return recordMalformed(raw);
        }
    }

    public Verdict recordMalformed(RawPacket raw) {
        stats.total++;
        stats.bytes += raw.data().length;
        stats.malformed++;
        stats.dropped++;
        return Verdict.DROP;
    }

    public Verdict recordUnsupported(RawPacket raw) {
        stats.total++;
        stats.bytes += raw.data().length;
        stats.other++;
        stats.forwarded++;
        return Verdict.FORWARD;
    }

    public Verdict processParsed(RawPacket raw, ParsedPacket pp) {
        stats.total++;
        stats.bytes += raw.data().length;
        if (pp.protocol() == 6) stats.tcp++; else stats.udp++;

        Flow flow = flows.update(pp, raw.data().length);
        classify(flow, pp, raw.data());
        if (!flow.blocked() && rules.isBlocked(flow)) flow.setBlocked(true);

        stats.countApp(flow.appType());

        if (flow.blocked()) {
            stats.dropped++;
            return Verdict.DROP;
        }
        stats.forwarded++;
        return Verdict.FORWARD;
    }

    private void classify(Flow flow, ParsedPacket pp, byte[] data) {
        if (flow.hostname() == null && pp.protocol() == 6 && pp.payloadLength() > 0) {
            Optional<String> host = Optional.empty();
            if (pp.dstPort() == 443) {
                host = SniExtractor.extract(data, pp.payloadOffset(), pp.payloadLength());
            } else if (pp.dstPort() == 80) {
                host = HttpHostExtractor.extract(data, pp.payloadOffset(), pp.payloadLength());
            }
            if (host.isPresent()) {
                flow.setHostname(host.get());
                AppType app = AppClassifier.fromHostname(host.get());
                if (app != AppType.UNKNOWN) flow.setAppType(app);
            }
        }
        if (flow.appType() == AppType.UNKNOWN) {
            flow.setAppType(fromPorts(pp));
        }
    }

    private static AppType fromPorts(ParsedPacket pp) {
        if (pp.srcPort() == 53 || pp.dstPort() == 53) return AppType.DNS;
        if (pp.protocol() == 6) {
            if (pp.srcPort() == 443 || pp.dstPort() == 443) return AppType.HTTPS;
            if (pp.srcPort() == 80 || pp.dstPort() == 80) return AppType.HTTP;
        }
        return AppType.UNKNOWN;
    }

    public Stats stats() { return stats; }
    public Collection<Flow> flows() { return flows.all(); }
    public String report() { return Report.format(stats, flows.all()); }
}
