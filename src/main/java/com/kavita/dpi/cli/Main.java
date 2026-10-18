package com.kavita.dpi.cli;

import com.kavita.dpi.concurrent.ParallelEngine;
import com.kavita.dpi.engine.DpiEngine;
import com.kavita.dpi.engine.Report;
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
        boolean parallel = false;
        int groups = 2;
        int workers = 2;
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
                case "--parallel" -> parallel = true;
                case "--groups" -> { groups = positive(args, ++i); parallel = true; }
                case "--workers" -> { workers = positive(args, ++i); parallel = true; }
                case "--block-app" -> {
                    String name = value(args, ++i);
                    rules.blockApp(AppType.parse(name)
                            .orElseThrow(() -> new IllegalArgumentException("Unknown app: " + name)));
                }
                default -> throw new IllegalArgumentException("Unknown option: " + args[i]);
            }
        }

        long start = System.nanoTime();
        try (PcapReader reader = PcapReader.open(Path.of(file))) {
            if (reader.header().linkType() != 1) {
                throw new PcapFormatException("Only Ethernet captures are supported (link type "
                        + reader.header().linkType() + ")");
            }
            PcapWriter writer = output == null
                    ? null
                    : PcapWriter.create(Path.of(output), reader.header());
            try {
                if (parallel) {
                    ParallelEngine.Outcome out =
                            new ParallelEngine(rules, groups, workers).run(reader, writer);
                    System.out.print(Report.format(out.stats(), out.flows()));
                    System.out.println("\nThreads: " + groups + " groups x " + workers + " workers");
                    out.threadLines().forEach(line -> System.out.println("  " + line));
                } else {
                    DpiEngine engine = new DpiEngine(rules);
                    Optional<RawPacket> next = reader.readNextPacket();
                    while (next.isPresent()) {
                        DpiEngine.Verdict verdict = engine.process(next.get());
                        if (writer != null && verdict == DpiEngine.Verdict.FORWARD) {
                            writer.write(next.get());
                        }
                        next = reader.readNextPacket();
                    }
                    System.out.print(engine.report());
                }
            } finally {
                if (writer != null) writer.close();
            }
        }
        double ms = (System.nanoTime() - start) / 1_000_000.0;
        System.out.printf("%nElapsed: %.1f ms%n", ms);
        if (output != null) System.out.println("Output written to: " + output);
    }

    private static String value(String[] args, int i) {
        if (i >= args.length) throw new IllegalArgumentException("Missing value for " + args[i - 1]);
        return args[i];
    }

    private static int positive(String[] args, int i) {
        int n = Integer.parseInt(value(args, i));
        if (n < 1) throw new IllegalArgumentException(args[i - 1] + " must be at least 1");
        return n;
    }
}
