package com.kavita.dpi.engine;

import com.kavita.dpi.model.AppType;
import com.kavita.dpi.model.FlowKey;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class EngineRulesTest {

    private static Flow flow(int initiatorIp, String host) {
        Flow f = new Flow(new FlowKey(1, 1, 2, 2, 6), initiatorIp, 50000);
        f.setHostname(host);
        return f;
    }

    @Test
    void classifiesBySuffixNotSubstring() {
        assertEquals(AppType.YOUTUBE, AppClassifier.fromHostname("www.youtube.com"));
        assertEquals(AppType.NETFLIX, AppClassifier.fromHostname("www.netflix.com"));
        assertEquals(AppType.MICROSOFT, AppClassifier.fromHostname("www.microsoft.com"));
        assertEquals(AppType.UNKNOWN, AppClassifier.fromHostname("www.dropbox.com"));
        assertEquals(AppType.UNKNOWN, AppClassifier.fromHostname("notyoutube.com"));
    }

    @Test
    void domainRuleMatchesSubdomainsOnly() {
        RuleSet rules = new RuleSet();
        rules.blockDomain("youtube.com");
        assertTrue(rules.isBlocked(flow(0, "www.youtube.com")));
        assertFalse(rules.isBlocked(flow(0, "notyoutube.com")));
    }

    @Test
    void ipRuleMatchesTheClient() {
        RuleSet rules = new RuleSet();
        rules.blockIp("192.168.1.100");
        assertTrue(rules.isBlocked(flow(0xC0A80164, null)));
        assertFalse(rules.isBlocked(flow(0xC0A80165, null)));
    }
}
