package com.kavita.dpi.engine;

import com.kavita.dpi.model.AppType;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public final class RuleSet {
    private final Set<Integer> blockedIps = new HashSet<>();
    private final Set<AppType> blockedApps = EnumSet.noneOf(AppType.class);
    private final List<String> blockedDomains = new ArrayList<>();

    public void blockIp(String dotted) {
        String[] parts = dotted.trim().split("\\.");
        if (parts.length != 4) throw new IllegalArgumentException("Bad IPv4 address: " + dotted);
        int ip = 0;
        for (String part : parts) {
            int octet;
            try {
                octet = Integer.parseInt(part);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Bad IPv4 address: " + dotted);
            }
            if (octet < 0 || octet > 255) throw new IllegalArgumentException("Bad IPv4 address: " + dotted);
            ip = (ip << 8) | octet;
        }
        blockedIps.add(ip);
    }

    public void blockApp(AppType app) { blockedApps.add(app); }

    public void blockDomain(String domain) {
        String d = domain.trim().toLowerCase(Locale.ROOT);
        if (d.startsWith("*.")) d = d.substring(2);
        if (d.startsWith(".")) d = d.substring(1);
        blockedDomains.add(d);
    }

    public boolean isBlocked(Flow flow) {
        if (blockedIps.contains(flow.initiatorIp())) return true;
        if (blockedApps.contains(flow.appType())) return true;
        String host = flow.hostname();
        if (host != null) {
            for (String d : blockedDomains) {
                if (AppClassifier.matchesDomain(host, d)) return true;
            }
        }
        return false;
    }
}
