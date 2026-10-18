package com.kavita.dpi.concurrent;

import java.util.List;
import java.util.concurrent.BlockingQueue;

public final class Dispatcher implements Runnable {
    private final BlockingQueue<Task> in;
    private final List<BlockingQueue<Task>> workerQueues;
    private final int groups;
    private long dispatched;

    public Dispatcher(BlockingQueue<Task> in, List<BlockingQueue<Task>> workerQueues, int groups) {
        this.in = in;
        this.workerQueues = workerQueues;
        this.groups = groups;
    }

    @Override
    public void run() {
        try {
            while (true) {
                Task task = in.take();
                if (task.kind() == Task.Kind.POISON) {
                    for (BlockingQueue<Task> q : workerQueues) q.put(Task.poison());
                    break;
                }
                int w = FlowHash.workerInGroup(task.hash(), groups, workerQueues.size());
                workerQueues.get(w).put(task);
                dispatched++;
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public long dispatched() { return dispatched; }
}
