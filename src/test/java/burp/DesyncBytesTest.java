package burp;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Pins the byte representation of the high-bit characters used by the
 * {@code spaceFF}, {@code unispace}, {@code nbsp}, {@code nel}, {@code shy},
 * and {@code shy2} desync permutations.
 *
 * <p>These bytes are essential for the permutations to actually exercise the
 * underlying parser quirks they target. On JVMs whose default charset is UTF-8
 * (the modern default), an accidental {@code new String(byte[])} or
 * {@code .getBytes()} on raw HTTP bytes mangles {@code 0x80}&ndash;{@code 0xFF}
 * into multi-byte UTF-8 sequences or replacement characters, silently
 * neutering the entire technique. The HTTP Request Smuggler ships with an
 * explicit {@link java.nio.charset.StandardCharsets#ISO_8859_1 ISO_8859_1}
 * convention for raw HTTP bytes; this test documents the bytes the rest of
 * the codebase must preserve verbatim through that convention.</p>
 *
 * <p>The test deliberately exercises the conversion strategy rather than
 * {@code DesyncBox.applyDesync} directly so that it can run in CI without
 * the closed-source PortSwigger dependency JARs being present.</p>
 */
class DesyncBytesTest {

    @Test
    void spaceFfByteRoundTripsCleanly() {
        byte expected = (byte) 0xFF;
        assertArrayEquals(new byte[]{expected}, isoRoundTrip(new byte[]{expected}),
                "0xFF (spaceFF) must survive an ISO-8859-1 byte->String->byte round-trip");
    }

    @Test
    void unispaceAndNbspByteRoundTripsCleanly() {
        byte expected = (byte) 0xA0;
        assertArrayEquals(new byte[]{expected}, isoRoundTrip(new byte[]{expected}),
                "0xA0 (unispace/nbsp) must survive an ISO-8859-1 round-trip");
    }

    @Test
    void nelByteRoundTripsCleanly() {
        byte expected = (byte) 0x85;
        assertArrayEquals(new byte[]{expected}, isoRoundTrip(new byte[]{expected}),
                "0x85 (NEL) must survive an ISO-8859-1 round-trip");
    }

    @Test
    void shyByteRoundTripsCleanly() {
        byte expected = (byte) 0xAD;
        assertArrayEquals(new byte[]{expected}, isoRoundTrip(new byte[]{expected}),
                "0xAD (SHY) must survive an ISO-8859-1 round-trip");
    }

    @Test
    void utf8RoundTripCorruptsHighBitBytes() {
        // Documents the failure mode the production charset fix prevents: decoding
        // raw HTTP bytes with the JVM default UTF-8 charset turns lone high-bit
        // bytes into the Unicode replacement character, then re-encoding emits
        // either the multi-byte UTF-8 form or 0x3F (?).
        byte[] roundTripped = new String(new byte[]{(byte) 0xA0}, StandardCharsets.UTF_8)
                .getBytes(StandardCharsets.UTF_8);
        assertEquals(false, java.util.Arrays.equals(new byte[]{(byte) 0xA0}, roundTripped),
                "UTF-8 should NOT round-trip a lone 0xA0 byte; if this test fails, "
                        + "the JVM is silently preserving bytes that production code "
                        + "would still corrupt on other platforms.");
    }

    @Test
    void nbspHeaderInsertionEmitsSingleByte() {
        // Mirrors DesyncBox.applyDesync case "nbsp":
        //   permuted = header.replace(":", "\u00A0:");
        // When encoded with ISO-8859-1 this MUST produce a single 0xA0 byte
        // at the insertion point. UTF-8 would emit 0xC2 0xA0 instead, two
        // bytes that the back-end parser would treat as a different
        // (well-formed) header value.
        String header = "Content-Length: ";
        String permuted = header.replace(":", "\u00A0:");
        byte[] bytes = permuted.getBytes(StandardCharsets.ISO_8859_1);

        assertEquals(header.length() + 1, bytes.length,
                "nbsp insertion should add exactly one byte over the original header");
        int nbspIdx = "Content-Length".length();
        assertEquals((byte) 0xA0, bytes[nbspIdx],
                "Expected raw 0xA0 byte at the nbsp insertion point");
    }

    @Test
    void shyHeaderReplacementEmitsSingleByte() {
        String header = "Content-Length: ";
        String permuted = header.replace("-", "\u00AD");
        byte[] bytes = permuted.getBytes(StandardCharsets.ISO_8859_1);

        assertEquals(header.length(), bytes.length,
                "shy replacement should not change the overall length of the header");
        int shyIdx = "Content".length();
        assertEquals((byte) 0xAD, bytes[shyIdx],
                "Expected raw 0xAD byte at the shy substitution point");
    }

    @Test
    void shy2HeaderInsertionEmitsSingleByte() {
        String header = "Content-Length: ";
        String permuted = header.replace(":", "\u00AD:");
        byte[] bytes = permuted.getBytes(StandardCharsets.ISO_8859_1);

        assertEquals(header.length() + 1, bytes.length);
        int idx = "Content-Length".length();
        assertEquals((byte) 0xAD, bytes[idx],
                "Expected raw 0xAD byte at the shy2 insertion point");
    }

    @Test
    void nelHeaderInsertionEmitsSingleByte() {
        String header = "Content-Length: ";
        String permuted = header.replace(":", "\u0085:");
        byte[] bytes = permuted.getBytes(StandardCharsets.ISO_8859_1);

        assertEquals(header.length() + 1, bytes.length);
        int idx = "Content-Length".length();
        assertEquals((byte) 0x85, bytes[idx],
                "Expected raw 0x85 byte at the NEL insertion point");
    }

    /**
     * Mirrors the production charset round-trip used by request inspection paths
     * such as {@code SuggestAttack#actionPerformed} and
     * {@code ConnectionStateScan#reflectScan}: decode raw HTTP bytes with
     * ISO-8859-1 and re-encode with the same charset. Bytes must come back
     * byte-identical, including {@code 0x80}&ndash;{@code 0xFF}.
     */
    private static byte[] isoRoundTrip(byte[] input) {
        String decoded = new String(input, StandardCharsets.ISO_8859_1);
        return decoded.getBytes(StandardCharsets.ISO_8859_1);
    }
}
