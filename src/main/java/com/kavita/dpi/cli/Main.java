package com.kavita.dpi.cli;

import com.kavita.dpi.engine.DpiEngine;
import com.kavita.dpi.engine.RuleSet;
import com.kavita.dpi.model.AppType;
import com.kavita.dpi.pcap.PcapFormatException;
import com.kavita.dpi.pcap.PcapReader;
import com.kavita.dpi.pcap.PcapWriter;
import com.kavita.dpi.pcap.RawPacket;

import java.nio.file.Path;
import java.util.Optional;

public class Main {
    public static void main(String[] args) throws Exception {
        String file = "test_dpi.pcap";
        String output = null;
        RuleSet rules = new RuleSet();

        int i = 0;
        if (args.length > 0 && !args[0].startsWith("--")) {
            file = args[0];
            i = 1;
        }
        for (; i < args.length; i++) {
            switch (args[i]) {
                case "--block-ip" -> rules.blockIp(value(args, ++i));
                case "--block-domain" -> rules.blockDomain(value(args, ++i));
                case "--output" -> output = value(args, ++i);
                case "--block-app" -> {
                    String name = value(args, ++i);
                    rules.blockApp(AppType.parse(name)
                            .orElseThrow(() -> new IllegalArgumentException("Unknown app: " + name)));
                }
                default -> throw new IllegalArgumentException("Unknown option: " + args[i]);
            }
        }

        DpiEngine engine = new DpiEngine(rules);
        try (PcapReader reader = PcapReader.open(Path.of(file))) {
            if (reader.header().linkType() != 1) {
                throw new PcapFormatException("Only Ethernet captures are supported (link type "
                        + reader.header().linkType() + ")");
            }
            PcapWriter writer = output == null
                    ? null
                    : PcapWriter.create(Path.of(output), reader.header());
            try {
                Optional<RawPacket> next = reader.readNextPacket();
                while (next.isPresent()) {
                    DpiEngine.Verdict verdict = engine.process(next.get());
                    if (writer != null && verdict == DpiEngine.Verdict.FORWARD) {
                        writer.write(next.get());
                    }
                    next = reader.readNextPacket();
                }
            } finally {
                if (writer != null) writer.close();
            }
        }
        System.out.print(engine.report());
        if (output != null) System.out.println("\nOutput written to: " + output);
    }

    private static String value(String[] args, int i) {
        if (i >= args.length) throw new IllegalArgumentException("Missing value for " + args[i - 1]);
        return args[i];
    }
}
