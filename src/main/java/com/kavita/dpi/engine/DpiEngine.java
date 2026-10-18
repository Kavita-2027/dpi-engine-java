package com.kavita.dpi.engine;

import com.kavita.dpi.extract.HttpHostExtractor;
import com.kavita.dpi.extract.SniExtractor;
import com.kavita.dpi.model.AppType;
import com.kavita.dpi.model.ParsedPacket;
import com.kavita.dpi.parser.PacketParseException;
import com.kavita.dpi.parser.PacketParser;
import com.kavita.dpi.pcap.RawPacket;

import java.util.Comparator;
import java.util.EnumMap;
import java.util.Map;
import java.util.Optional;

public final class DpiEngine {
    public enum Verdict { FORWARD, DROP }

    private final RuleSet rules;
    private final FlowTable flows = new FlowTable();
    private final Map<AppType, Long> appPackets = new EnumMap<>(AppType.class);
    private long total, bytes, tcp, udp, other, malformed, forwarded, dropped;

    public DpiEngine(RuleSet rules) { this.rules = rules; }

    public Verdict process(RawPacket raw) {
        total++;
        bytes += raw.data().length;

        ParsedPacket pp;
        try {
            Optional<ParsedPacket> parsed = PacketParser.parse(raw);
            if (parsed.isEmpty()) {
                other++;
                forwarded++;
                return Verdict.FORWARD;
            }
            pp = parsed.get();
        } catch (PacketParseException e) {
            malformed++;
            dropped++;
            return Verdict.DROP;
        }

        if (pp.protocol() == 6) tcp++; else udp++;

        Flow flow = flows.update(pp, raw.data().length);
        classify(flow, pp, raw.data());
        if (!flow.blocked() && rules.isBlocked(flow)) flow.setBlocked(true);

        appPackets.merge(flow.appType(), 1L, Long::sum);

        if (flow.blocked()) {
            dropped++;
            return Verdict.DROP;
        }
        forwarded++;
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

    public String report() {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("Total packets: %d  (%d bytes)%n", total, bytes));
        sb.append(String.format("TCP: %d  UDP: %d  Other: %d  Malformed: %d%n", tcp, udp, other, malformed));
        sb.append(String.format("Forwarded: %d  Dropped: %d%n", forwarded, dropped));
        sb.append(String.format("Flows: %d%n%n", flows.size()));

        sb.append("Application breakdown (packets):\n");
        appPackets.entrySet().stream()
                .sorted(Map.Entry.<AppType, Long>comparingByValue().reversed())
                .forEach(e -> sb.append(String.format("  %-11s %4d  (%.1f%%)%n",
                        e.getKey(), e.getValue(), 100.0 * e.getValue() / total)));

        sb.append("\nDetected domains:\n");
        flows.all().stream()
                .filter(f -> f.hostname() != null)
                .sorted(Comparator.comparing(Flow::hostname))
                .forEach(f -> sb.append(String.format("  %-24s -> %-10s %s%n",
                        f.hostname(), f.appType(), f.blocked() ? "(BLOCKED)" : "")));
        return sb.toString();
    }
}
