package com.kavita.dpi.concurrent;

import com.kavita.dpi.engine.DpiEngine;
import com.kavita.dpi.engine.RuleSet;
import com.kavita.dpi.model.FlowKey;
import com.kavita.dpi.pcap.PcapGlobalHeader;
import com.kavita.dpi.pcap.PcapReader;
import com.kavita.dpi.pcap.PcapWriter;
import com.kavita.dpi.pcap.RawPacket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class ParallelEngineTest {

    private static byte[] tcpFrame(int srcIp, int srcPort, int dstIp, int dstPort, byte[] payload) {
        ByteBuffer b = ByteBuffer.allocate(14 + 20 + 20 + payload.length);
        b.put(new byte[]{0, 1, 2, 3, 4, 5});
        b.put(new byte[]{6, 7, 8, 9, 10, 11});
        b.putShort((short) 0x0800);
        b.put((byte) 0x45);
        b.put((byte) 0);
        b.putShort((short) (40 + payload.length));
        b.putShort((short) 0);
        b.putShort((short) 0);
        b.put((byte) 64);
        b.put((byte) 6);
        b.putShort((short) 0);
        b.putInt(srcIp);
        b.putInt(dstIp);
        b.putShort((short) srcPort);
        b.putShort((short) dstPort);
        b.putInt(0);
        b.putInt(0);
        b.put((byte) 0x50);
        b.put((byte) 0x18);
        b.putShort((short) 65535);
        b.putShort((short) 0);
        b.putShort((short) 0);
        b.put(payload);
        return b.array();
    }

    private static byte[] buildCapture(int flows) throws IOException {
        PcapGlobalHeader h = new PcapGlobalHeader(ByteOrder.LITTLE_ENDIAN, false, 2, 4, 65535, 1);
        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        String[] hosts = {"www.youtube.com", "www.example.com", "www.netflix.com", "github.com"};
        byte[] none = new byte[0];
        byte[] reply = "HTTP/1.1 200 OK\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1);
        try (PcapWriter w = new PcapWriter(sink, h)) {
            long ts = 0;
            for (int f = 0; f < flows; f++) {
                int client = 0xC0A80100 + (f % 250);
                int server = 0x0A000000 + f;
                int cport = 40000 + f;
                byte[] req = ("GET / HTTP/1.1\r\nHost: " + hosts[f % hosts.length] + "\r\n\r\n")
                        .getBytes(StandardCharsets.ISO_8859_1);
                w.write(new RawPacket(ts++, 0, 60, tcpFrame(client, cport, server, 80, none)));
                w.write(new RawPacket(ts++, 0, 60, tcpFrame(client, cport, server, 80, req)));
                w.write(new RawPacket(ts++, 0, 60, tcpFrame(server, 80, client, cport, reply)));
                w.write(new RawPacket(ts++, 0, 60, tcpFrame(client, cport, server, 80, none)));
            }
            w.write(new RawPacket(ts, 0, 10, new byte[10]));
        }
        return sink.toByteArray();
    }

    @ParameterizedTest
    @CsvSource({"1,1", "2,2", "1,3", "3,1"})
    void parallelOutputMatchesSingleThreaded(int groups, int workers) throws Exception {
        byte[] capture = buildCapture(200);
        RuleSet rules = new RuleSet();
        rules.blockDomain("youtube.com");

        ByteArrayOutputStream single = new ByteArrayOutputStream();
        DpiEngine engine = new DpiEngine(rules);
        try (PcapReader r = new PcapReader(new ByteArrayInputStream(capture));
             PcapWriter w = new PcapWriter(single, r.header())) {
            Optional<RawPacket> next = r.readNextPacket();
            while (next.isPresent()) {
                if (engine.process(next.get()) == DpiEngine.Verdict.FORWARD) w.write(next.get());
                next = r.readNextPacket();
            }
        }

        ByteArrayOutputStream parallel = new ByteArrayOutputStream();
        ParallelEngine.Outcome outcome;
        try (PcapReader r = new PcapReader(new ByteArrayInputStream(capture));
             PcapWriter w = new PcapWriter(parallel, r.header())) {
            outcome = new ParallelEngine(rules, groups, workers).run(r, w);
        }

        assertArrayEquals(single.toByteArray(), parallel.toByteArray());
        assertEquals(engine.stats().total(), outcome.stats().total());
        assertEquals(engine.stats().forwarded(), outcome.stats().forwarded());
        assertEquals(engine.stats().dropped(), outcome.stats().dropped());
        assertEquals(engine.stats().malformed(), outcome.stats().malformed());
        assertEquals(engine.flows().size(), outcome.flows().size());
    }

    @Test
    void twoLevelHashUsesAllFourWorkers() {
        int[] counts = new int[4];
        for (int i = 0; i < 1000; i++) {
            FlowKey key = new FlowKey(0xC0A80101, 40000 + i, 0x0A000001, 443, 6);
            int h = FlowHash.of(key);
            int g = FlowHash.group(h, 2);
            int w = FlowHash.workerInGroup(h, 2, 2);
            counts[g * 2 + w]++;
        }
        for (int c : counts) {
            assertTrue(c > 100, "skewed distribution: " + Arrays.toString(counts));
        }
    }
}
