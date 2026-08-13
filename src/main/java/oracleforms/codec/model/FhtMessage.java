package oracleforms.codec.model;

import java.util.List;

/**
 * One message within an FHT packet: an action on a class, addressed to a handler, carrying
 * properties.
 *
 * <p>{@code rawHeader} is the header word exactly as read. It is kept because class-id extraction is
 * <em>unverified</em>: the reference masked with {@code 0x3FF} and then tested {@code >= 2000}, a
 * branch that can never fire (architecture &sect;7.1). We mask with {@code 0x0FFF}, which makes that
 * branch reachable and is the likelier intent, but keeping the raw word means the question can be
 * settled from a capture without re-decoding anything.
 */
public record FhtMessage(
        String action,
        int classId,
        int handlerId,
        List<FhtProperty> properties,
        int offset,
        int rawHeader) {

    public FhtMessage {
        properties = List.copyOf(properties);
    }

    /** Properties whose ids are flagged as carrying secrets. */
    public List<FhtProperty> sensitiveProperties() {
        return properties.stream().filter(FhtProperty::isSensitive).toList();
    }
}
