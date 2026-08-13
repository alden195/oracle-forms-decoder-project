package oracleforms.codec.model;

import java.util.List;

/**
 * A parsed FHT packet: the messages recovered, plus how the parse ended.
 *
 * <p>Both halves matter. A packet with messages and a {@link ParseOutcome.Truncated} outcome is a
 * real, useful, partial decode — the UI shows what was recovered and says where it stopped.
 */
public record FhtPacket(List<FhtMessage> messages, ParseOutcome outcome, int byteLength) {

    public FhtPacket {
        messages = List.copyOf(messages);
    }

    public boolean isEmpty() {
        return messages.isEmpty();
    }

    public boolean hasSensitiveValues() {
        return messages.stream().anyMatch(m -> !m.sensitiveProperties().isEmpty());
    }
}
