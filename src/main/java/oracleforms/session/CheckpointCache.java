package oracleforms.session;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Optional;
import java.util.TreeMap;

/**
 * Bounded, in-memory cache of {@link Checkpoint}s, keyed by session and direction.
 *
 * <p>Bounded in two dimensions, because both can run away on a large project: the number of streams
 * tracked, and the number of checkpoints kept per stream. The reference implementation's equivalent
 * (`_pre_state`, a 256-entry list per pragma per direction) was unbounded and is exactly the kind of
 * thing BApp criterion 9 is about.
 *
 * <p>When a stream is full it is <em>thinned</em> rather than truncated: every second checkpoint is
 * dropped, doubling the effective interval while keeping coverage spread across the whole session.
 * Discarding the oldest instead would be worse than useless — the early checkpoints are the ones
 * that make the start of a session cheap to reach, and they are the most expensive to rebuild.
 *
 * <p>Thread safe by coarse synchronization. Contention is not a concern: decodes are serialized on a
 * small executor, and the critical sections are map operations.
 */
public final class CheckpointCache {

    private static final int DEFAULT_MAX_STREAMS = 16;
    private static final int DEFAULT_MAX_PER_STREAM = 32;

    private record StreamKey(String sessionId, Direction direction) {
    }

    private final int maxPerStream;
    private final Map<StreamKey, NavigableMap<Integer, Checkpoint>> streams;

    public CheckpointCache() {
        this(DEFAULT_MAX_STREAMS, DEFAULT_MAX_PER_STREAM);
    }

    public CheckpointCache(int maxStreams, int maxPerStream) {
        this.maxPerStream = Math.max(2, maxPerStream);
        this.streams = new LinkedHashMap<>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<StreamKey, NavigableMap<Integer, Checkpoint>> e) {
                return size() > Math.max(1, maxStreams);
            }
        };
    }

    /** The latest checkpoint at or below {@code pragma}, if one is cached. */
    public synchronized Optional<Checkpoint> nearestAtOrBefore(
            String sessionId, Direction direction, int pragma) {
        NavigableMap<Integer, Checkpoint> stream = streams.get(new StreamKey(sessionId, direction));
        if (stream == null) {
            return Optional.empty();
        }
        Map.Entry<Integer, Checkpoint> entry = stream.floorEntry(pragma);
        return entry == null ? Optional.empty() : Optional.of(entry.getValue());
    }

    public synchronized void put(String sessionId, Direction direction, Checkpoint checkpoint) {
        NavigableMap<Integer, Checkpoint> stream =
                streams.computeIfAbsent(new StreamKey(sessionId, direction), k -> new TreeMap<>());
        stream.put(checkpoint.pragma(), checkpoint);
        if (stream.size() > maxPerStream) {
            thin(stream);
        }
    }

    /**
     * Halves a stream by dropping every second checkpoint, keeping the first and the last. The last
     * matters most — it is where the user is reading — and the first keeps a cheap anchor near the
     * start of the session.
     */
    private void thin(NavigableMap<Integer, Checkpoint> stream) {
        List<Integer> keys = new ArrayList<>(stream.keySet());
        for (int i = 1; i < keys.size() - 1; i += 2) {
            stream.remove(keys.get(i));
        }
    }

    /** Drops everything cached for a session, both directions. Called when its key changes. */
    public synchronized void invalidate(String sessionId) {
        streams.keySet().removeIf(k -> k.sessionId().equals(sessionId));
    }

    /** Releases all state. Called on extension unload (BApp criterion 6). */
    public synchronized void clear() {
        streams.clear();
    }

    synchronized int checkpointCount() {
        return streams.values().stream().mapToInt(Map::size).sum();
    }
}
