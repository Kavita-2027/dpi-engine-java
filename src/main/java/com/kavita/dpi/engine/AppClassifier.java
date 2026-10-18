package com.kavita.dpi.engine;

import com.kavita.dpi.model.AppType;

import java.util.HashMap;
import java.util.Map;

public final class AppClassifier {
    private static final Map<String, AppType> SUFFIXES = new HashMap<>();

    private static void add(AppType app, String... domains) {
        for (String d : domains) SUFFIXES.put(d, app);
    }

    static {
        add(AppType.GOOGLE, "google.com", "gstatic.com", "googleapis.com", "ggpht.com", "gvt1.com");
        add(AppType.YOUTUBE, "youtube.com", "youtu.be", "ytimg.com", "googlevideo.com");
        add(AppType.FACEBOOK, "facebook.com", "fbcdn.net", "fb.com", "fbsbx.com", "meta.com");
        add(AppType.INSTAGRAM, "instagram.com", "cdninstagram.com");
        add(AppType.WHATSAPP, "whatsapp.com", "whatsapp.net", "wa.me");
        add(AppType.TWITTER, "twitter.com", "x.com", "twimg.com", "t.co");
        add(AppType.NETFLIX, "netflix.com", "nflxvideo.net", "nflximg.net");
        add(AppType.AMAZON, "amazon.com", "amazonaws.com", "cloudfront.net");
        add(AppType.MICROSOFT, "microsoft.com", "live.com", "office.com", "office365.com",
                "outlook.com", "bing.com", "msn.com", "azure.com");
        add(AppType.APPLE, "apple.com", "icloud.com", "mzstatic.com", "itunes.com");
        add(AppType.TELEGRAM, "telegram.org", "t.me");
        add(AppType.TIKTOK, "tiktok.com", "tiktokcdn.com", "bytedance.com", "musical.ly");
        add(AppType.SPOTIFY, "spotify.com", "scdn.co");
        add(AppType.ZOOM, "zoom.us", "zoom.com");
        add(AppType.DISCORD, "discord.com", "discordapp.com");
        add(AppType.GITHUB, "github.com", "githubusercontent.com");
        add(AppType.CLOUDFLARE, "cloudflare.com");
    }

    private AppClassifier() {}

    public static AppType fromHostname(String host) {
        String s = host;
        while (true) {
            AppType t = SUFFIXES.get(s);
            if (t != null) return t;
            int dot = s.indexOf('.');
            if (dot < 0) return AppType.UNKNOWN;
            s = s.substring(dot + 1);
        }
    }

    public static boolean matchesDomain(String host, String domain) {
        return host.equals(domain) || host.endsWith("." + domain);
    }
}