package com.kavita.dpi.engine;

import com.kavita.dpi.model.AppType;

import java.util.Collection;
import java.util.Comparator;
import java.util.Map;

public final class Report {
    private Report() {}

    public static String format(Stats s, Collection<Flow> flows) {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("Total packets: %d  (%d bytes)%n", s.total, s.bytes));
        sb.append(String.format("TCP: %d  UDP: %d  Other: %d  Malformed: %d%n",
                s.tcp, s.udp, s.other, s.malformed));
        sb.append(String.format("Forwarded: %d  Dropped: %d%n", s.forwarded, s.dropped));
        sb.append(String.format("Flows: %d%n%n", flows.size()));

        sb.append("Application breakdown (packets):\n");
        s.appPackets.entrySet().stream()
                .sorted(Map.Entry.<AppType, Long>comparingByValue().reversed())
                .forEach(e -> sb.append(String.format("  %-11s %4d  (%.1f%%)%n",
                        e.getKey(), e.getValue(),
                        s.total == 0 ? 0.0 : 100.0 * e.getValue() / s.total)));

        sb.append("\nDetected domains:\n");
        flows.stream()
                .filter(f -> f.hostname() != null)
                .sorted(Comparator.comparing(Flow::hostname))
                .forEach(f -> sb.append(String.format("  %-24s -> %-10s %s%n",
                        f.hostname(), f.appType(), f.blocked() ? "(BLOCKED)" : "")));
        return sb.toString();
    }
}
