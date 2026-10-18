package com.kavita.dpi.concurrent;

import com.kavita.dpi.pcap.PcapWriter;

import java.io.IOException;
import java.util.TreeMap;
import java.util.concurrent.BlockingQueue;

public final class OrderedWriter implements Runnable {
    private final BlockingQueue<Result> in;
    private final PcapWriter writer;
    private final int producers;
    private volatile Exception failure;

    public OrderedWriter(BlockingQueue<Result> in, PcapWriter writer, int producers) {
        this.in = in;
        this.writer = writer;
        this.producers = producers;
    }

    @Override
    public void run() {
        TreeMap<Long, Result> pending = new TreeMap<>();
        long next = 0;
        int doneCount = 0;
        boolean failed = false;
        try {
            while (doneCount < producers) {
                Result r = in.take();
                if (r.done()) {
                    doneCount++;
                    continue;
                }
                pending.put(r.seq(), r);
                while (!pending.isEmpty() && pending.firstKey().longValue() == next) {
                    Result ready = pending.pollFirstEntry().getValue();
                    if (writer != null && !failed && ready.forward()) {
                        try {
                            writer.write(ready.raw());
                        } catch (IOException e) {
                            failure = e;
                            failed = true;
                        }
                    }
                    next++;
                }
            }
            if (!pending.isEmpty() && failure == null) {
                failure = new IllegalStateException(pending.size() + " packets were never written");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public Exception failure() { return failure; }
}
