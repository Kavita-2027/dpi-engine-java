package com.kavita.dpi.concurrent;

import com.kavita.dpi.model.FlowKey;

final class FlowHash {
    private FlowHash() {}

    static int of(FlowKey key) {
        return mix(key.hashCode());
    }

    /** Spreads bits so that different parts of the result are independent of each other. */
    static int mix(int h) {
        h ^= h >>> 16;
        h *= 0x85ebca6b;
        h ^= h >>> 13;
        h *= 0xc2b2ae35;
        h ^= h >>> 16;
        return h;
    }

    static int group(int hash, int groups) {
        return Integer.remainderUnsigned(hash, groups);
    }

    static int workerInGroup(int hash, int groups, int workersPerGroup) {
        return Integer.remainderUnsigned(Integer.divideUnsigned(hash, groups), workersPerGroup);
    }
}
