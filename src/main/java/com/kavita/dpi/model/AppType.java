package com.kavita.dpi.model;

import java.util.Locale;
import java.util.Optional;

public enum AppType {
    UNKNOWN, HTTP, HTTPS, DNS,
    GOOGLE, YOUTUBE, FACEBOOK, INSTAGRAM, WHATSAPP, TWITTER, NETFLIX, AMAZON,
    MICROSOFT, APPLE, TELEGRAM, TIKTOK, SPOTIFY, ZOOM, DISCORD, GITHUB, CLOUDFLARE;

    public static Optional<AppType> parse(String name) {
        String n = name.trim().toLowerCase(Locale.ROOT);
        if (n.equals("x") || n.equals("twitter/x")) return Optional.of(TWITTER);
        for (AppType t : values()) {
            if (t.name().toLowerCase(Locale.ROOT).equals(n)) return Optional.of(t);
        }
        return Optional.empty();
    }
}
