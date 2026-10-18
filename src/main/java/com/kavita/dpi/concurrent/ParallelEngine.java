package com.kavita.dpi.concurrent;

import com.kavita.dpi.engine.Flow;
import com.kavita.dpi.engine.RuleSet;
import com.kavita.dpi.engine.Stats;
import com.kavita.dpi.model.FlowKey;
import com.kavita.dpi.model.ParsedPacket;
import com.kavita.dpi.parser.PacketParseException;
import com.kavita.dpi.parser.PacketParser;
import com.kavita.dpi.pcap.PcapReader;
import com.kavita.dpi.pcap.PcapWriter;
import com.kavita.dpi.pcap.RawPacket;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.atomic.AtomicReference;

public final class ParallelEngine {
    private static final int TASK_QUEUE_CAPACITY = 1024;
    private static final int RESULT_QUEUE_CAPACITY = 4096;

    public record Outcome(Stats stats, List<Flow> flows, List<String> threadLines) {}

    private final RuleSet rules;
    private final int groups;
    private final int workersPerGroup;

    public ParallelEngine(RuleSet rules, int groups, int workersPerGroup) {
        if (groups < 1 || workersPerGroup < 1) {
            throw new IllegalArgumentException("groups and workers must be at least 1");
        }
        this.rules = rules;
        this.groups = groups;
        this.workersPerGroup = workersPerGroup;
    }

    public Outcome run(PcapReader reader, PcapWriter writer) throws Exception {
        int totalWorkers = groups * workersPerGroup;
        BlockingQueue<Result> results = new ArrayBlockingQueue<>(RESULT_QUEUE_CAPACITY);

        List<BlockingQueue<Task>> dispatcherQueues = new ArrayList<>();
        List<Dispatcher> dispatchers = new ArrayList<>();
        List<Worker> workers = new ArrayList<>();
        List<Thread> threads = new ArrayList<>();

        Thread mainThread = Thread.currentThread();
        AtomicReference<Throwable> firstError = new AtomicReference<>();
        Thread.UncaughtExceptionHandler handler = (t, e) -> {
            firstError.compareAndSet(null, e);
            mainThread.interrupt();
        };

        OrderedWriter orderedWriter = new OrderedWriter(results, writer, totalWorkers);

        for (int g = 0; g < groups; g++) {
            List<BlockingQueue<Task>> workerQueues = new ArrayList<>();
            for (int w = 0; w < workersPerGroup; w++) {
                BlockingQueue<Task> q = new ArrayBlockingQueue<>(TASK_QUEUE_CAPACITY);
                workerQueues.add(q);
                Worker worker = new Worker(q, results, rules);
                workers.add(worker);
                threads.add(newThread(worker, "dpi-worker-" + g + "-" + w, handler));
            }
            BlockingQueue<Task> dq = new ArrayBlockingQueue<>(TASK_QUEUE_CAPACITY);
            dispatcherQueues.add(dq);
            Dispatcher dispatcher = new Dispatcher(dq, workerQueues, groups);
            dispatchers.add(dispatcher);
            threads.add(newThread(dispatcher, "dpi-dispatcher-" + g, handler));
        }
        threads.add(newThread(orderedWriter, "dpi-writer", handler));
        for (Thread t : threads) t.start();

        boolean ok = false;
        try {
            long seq = 0;
            Optional<RawPacket> next = reader.readNextPacket();
            while (next.isPresent()) {
                Task task = makeTask(seq++, next.get());
                dispatcherQueues.get(FlowHash.group(task.hash(), groups)).put(task);
                next = reader.readNextPacket();
            }
            for (BlockingQueue<Task> q : dispatcherQueues) q.put(Task.poison());
            for (Thread t : threads) t.join();
            ok = true;
        } catch (InterruptedException e) {
            Throwable cause = firstError.get();
            if (cause != null) throw new IllegalStateException("A pipeline thread failed", cause);
            throw e;
        } finally {
            if (!ok) {
                for (Thread t : threads) t.interrupt();
                for (Thread t : threads) {
                    try {
                        t.join();
                    } catch (InterruptedException ignored) {
                        // already shutting down
                    }
                }
            }
        }

        if (firstError.get() != null) {
            throw new IllegalStateException("A pipeline thread failed", firstError.get());
        }
        if (orderedWriter.failure() != null) {
            throw new IOException("Writing the output failed", orderedWriter.failure());
        }

        Stats total = new Stats();
        List<Flow> flows = new ArrayList<>();
        List<String> lines = new ArrayList<>();
        for (int g = 0; g < dispatchers.size(); g++) {
            lines.add(String.format("Dispatcher %d dispatched: %d", g, dispatchers.get(g).dispatched()));
        }
        for (int i = 0; i < workers.size(); i++) {
            Worker w = workers.get(i);
            total.merge(w.engine().stats());
            flows.addAll(w.engine().flows());
            lines.add(String.format("Worker %d.%d processed: %d",
                    i / workersPerGroup, i % workersPerGroup, w.processed()));
        }
        return new Outcome(total, flows, lines);
    }

    private static Task makeTask(long seq, RawPacket raw) {
        try {
            Optional<ParsedPacket> parsed = PacketParser.parse(raw);
            if (parsed.isEmpty()) {
                return new Task(Task.Kind.UNSUPPORTED, seq, FlowHash.mix((int) seq), raw, null);
            }
            int hash = FlowHash.of(FlowKey.of(parsed.get()));
            return new Task(Task.Kind.PARSED, seq, hash, raw, parsed.get());
        } catch (PacketParseException e) {
            return new Task(Task.Kind.MALFORMED, seq, FlowHash.mix((int) seq), raw, null);
        }
    }

    private static Thread newThread(Runnable r, String name, Thread.UncaughtExceptionHandler h) {
        Thread t = new Thread(r, name);
        t.setUncaughtExceptionHandler(h);
        return t;
    }
}
