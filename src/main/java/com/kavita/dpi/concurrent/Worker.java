package com.kavita.dpi.concurrent;

import com.kavita.dpi.engine.DpiEngine;
import com.kavita.dpi.engine.RuleSet;

import java.util.concurrent.BlockingQueue;

public final class Worker implements Runnable {
    private final BlockingQueue<Task> in;
    private final BlockingQueue<Result> out;
    private final DpiEngine engine;
    private long processed;

    public Worker(BlockingQueue<Task> in, BlockingQueue<Result> out, RuleSet rules) {
        this.in = in;
        this.out = out;
        this.engine = new DpiEngine(rules);
    }

    @Override
    public void run() {
        try {
            while (true) {
                Task task = in.take();
                if (task.kind() == Task.Kind.POISON) break;

                DpiEngine.Verdict verdict = switch (task.kind()) {
                    case PARSED -> engine.processParsed(task.raw(), task.parsed());
                    case UNSUPPORTED -> engine.recordUnsupported(task.raw());
                    case MALFORMED -> engine.recordMalformed(task.raw());
                    case POISON -> throw new IllegalStateException("unreachable");
                };
                processed++;
                out.put(new Result(task.seq(), task.raw(),
                        verdict == DpiEngine.Verdict.FORWARD, false));
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            try {
                out.put(Result.finished());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    public DpiEngine engine() { return engine; }
    public long processed() { return processed; }
}
