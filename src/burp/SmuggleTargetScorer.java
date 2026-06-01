package burp;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Pure-function scorer that ranks HTTP requests by their suitability as a
 * request-smuggling probe target. Deliberately holds no references to Burp or
 * PortSwigger APIs so it can run in the independent test source set declared
 * in {@code build.gradle} without the closed-source dependency JARs being
 * present.
 *
 * <p>Inputs are pure DTOs ({@link ParsedRequest}, {@link ParsedResponse})
 * carrying only primitives, strings, and a {@code Map<String, String>} of
 * headers keyed by their <strong>lowercased</strong> name. The Tab class is
 * responsible for projecting Burp's {@code HttpRequestResponse} into these
 * DTOs.</p>
 *
 * <p>Each scoring rule emits a {@link Reason} entry so the UI can render a
 * transparent breakdown rather than a single opaque number. Negative deltas
 * are recorded the same way so the operator can see why a candidate sank.</p>
 */
public final class SmuggleTargetScorer {

    private SmuggleTargetScorer() {
    }

    private static final Set<String> STATIC_ASSET_EXTENSIONS = Set.of(
            ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico",
            ".svg", ".woff", ".woff2", ".map", ".json"
    );

    public static ScoreResult score(ParsedRequest req, ParsedResponse resp) {
        List<Reason> reasons = new ArrayList<>();
        int total = 0;

        String method = req.method == null ? "" : req.method.toUpperCase(Locale.ROOT);
        int methodScore = methodScore(method);
        if (methodScore != 0) {
            reasons.add(new Reason("Method " + method, methodScore));
            total += methodScore;
        }

        if (req.contentLength > 0) {
            int delta = 20;
            reasons.add(new Reason("Content-Length=" + req.contentLength, delta));
            total += delta;
        }

        String contentType = req.headers.get("content-type");
        if (isParseableBody(contentType)) {
            int delta = 10;
            reasons.add(new Reason("Parseable Content-Type", delta));
            total += delta;
        }

        if (req.isHttp2) {
            int delta = 10;
            reasons.add(new Reason("HTTP/2 capable target", delta));
            total += delta;
        }

        if (hasCdnMarkers(resp.headers)) {
            int delta = 15;
            reasons.add(new Reason("CDN/edge markers in response", delta));
            total += delta;
        }

        if (hasBackendProcessingSignals(resp.headers)) {
            int delta = 5;
            reasons.add(new Reason("Back-end processing signals", delta));
            total += delta;
        }

        String respConnection = resp.headers.get("connection");
        if (respConnection != null && respConnection.toLowerCase(Locale.ROOT).contains("keep-alive")) {
            int delta = 5;
            reasons.add(new Reason("Connection: keep-alive", delta));
            total += delta;
        }

        if (isLikelyStaticAsset(req)) {
            int delta = -50;
            reasons.add(new Reason("Static asset extension", delta));
            total += delta;
        }

        if (resp.status == 0) {
            int delta = -100;
            reasons.add(new Reason("No response captured", delta));
            total += delta;
        } else if (resp.status >= 400 && resp.status < 500) {
            // 401/403/429 are kept neutral because they are typical for protected
            // endpoints that are still very much worth probing for smuggling.
            if (resp.status != 401 && resp.status != 403 && resp.status != 429) {
                int delta = -10;
                reasons.add(new Reason("Client error " + resp.status, delta));
                total += delta;
            }
        } else if (resp.status >= 500) {
            int delta = -5;
            reasons.add(new Reason("Server error " + resp.status, delta));
            total += delta;
        }

        String dedupKey = buildDedupKey(req.host, method, req.path);
        return new ScoreResult(total, reasons, dedupKey);
    }

    /**
     * Collapses a request path into a coarse template so multiple requests
     * against the same endpoint shape collapse into a single candidate.
     * Numeric and UUID/long-hex segments become {@code *}; the query string
     * is dropped because almost all smuggling techniques are
     * query-string-independent.
     */
    public static String normalizePath(String path) {
        if (path == null) {
            return "";
        }
        int q = path.indexOf('?');
        String p = q >= 0 ? path.substring(0, q) : path;
        String[] segments = p.split("/", -1);
        StringBuilder out = new StringBuilder(p.length());
        for (int i = 0; i < segments.length; i++) {
            if (i > 0) {
                out.append('/');
            }
            String segment = segments[i];
            if (looksLikeIdentifier(segment)) {
                out.append('*');
            } else {
                out.append(segment);
            }
        }
        return out.toString();
    }

    static String buildDedupKey(String host, String method, String path) {
        String h = host == null ? "" : host.toLowerCase(Locale.ROOT);
        String m = method == null ? "" : method.toUpperCase(Locale.ROOT);
        return h + "|" + m + "|" + normalizePath(path);
    }

    private static int methodScore(String method) {
        switch (method) {
            case "POST":
                return 30;
            case "PUT":
            case "PATCH":
                return 25;
            case "GET":
                return 10;
            case "HEAD":
            case "OPTIONS":
                return 5;
            default:
                return 0;
        }
    }

    private static boolean isParseableBody(String contentType) {
        if (contentType == null) {
            return false;
        }
        String ct = contentType.toLowerCase(Locale.ROOT);
        return ct.startsWith("application/x-www-form-urlencoded")
                || ct.startsWith("application/json")
                || ct.startsWith("application/xml")
                || ct.startsWith("text/xml")
                || ct.startsWith("multipart/")
                || ct.startsWith("text/plain");
    }

    private static boolean hasCdnMarkers(Map<String, String> respHeaders) {
        for (String name : respHeaders.keySet()) {
            if ("cf-ray".equals(name) || "cf-mitigated".equals(name)
                    || name.startsWith("x-amz-cf-")
                    || name.startsWith("x-fastly-")
                    || "x-served-by".equals(name)) {
                return true;
            }
        }
        String server = respHeaders.get("server");
        if (server != null) {
            String s = server.toLowerCase(Locale.ROOT);
            if (s.contains("akamaighost") || s.contains("cloudflare") || s.contains("cloudfront")) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasBackendProcessingSignals(Map<String, String> respHeaders) {
        if (respHeaders.containsKey("set-cookie")) {
            return true;
        }
        String cacheControl = respHeaders.get("cache-control");
        if (cacheControl != null && cacheControl.toLowerCase(Locale.ROOT).contains("private")) {
            return true;
        }
        if (respHeaders.containsKey("x-powered-by")) {
            return true;
        }
        String server = respHeaders.get("server");
        return server != null && !server.isBlank();
    }

    private static boolean isLikelyStaticAsset(ParsedRequest req) {
        if (!"GET".equalsIgnoreCase(req.method)) {
            return false;
        }
        if (req.query != null && !req.query.isEmpty()) {
            return false;
        }
        String path = req.path == null ? "" : req.path.toLowerCase(Locale.ROOT);
        int q = path.indexOf('?');
        if (q >= 0) {
            path = path.substring(0, q);
        }
        int dot = path.lastIndexOf('.');
        if (dot < 0 || dot < path.lastIndexOf('/')) {
            return false;
        }
        String ext = path.substring(dot);
        return STATIC_ASSET_EXTENSIONS.contains(ext);
    }

    private static boolean looksLikeIdentifier(String segment) {
        if (segment.isEmpty()) {
            return false;
        }
        // Pure numeric segments (e.g. /users/123)
        boolean allDigits = true;
        for (int i = 0; i < segment.length(); i++) {
            if (!Character.isDigit(segment.charAt(i))) {
                allDigits = false;
                break;
            }
        }
        if (allDigits) {
            return true;
        }
        // UUID 8-4-4-4-12
        if (segment.length() == 36 && segment.charAt(8) == '-' && segment.charAt(13) == '-'
                && segment.charAt(18) == '-' && segment.charAt(23) == '-'
                && isHexExceptDashes(segment)) {
            return true;
        }
        // Long hex hash (md5/sha and similar)
        if (segment.length() >= 32 && isAllHex(segment)) {
            return true;
        }
        return false;
    }

    private static boolean isHexExceptDashes(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '-') {
                continue;
            }
            if (!isHex(c)) {
                return false;
            }
        }
        return true;
    }

    private static boolean isAllHex(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (!isHex(s.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    private static boolean isHex(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    /** Result of scoring one request: a numeric total, the reasons that produced it, and a dedupe key. */
    public static final class ScoreResult {
        public final int score;
        public final List<Reason> reasons;
        public final String dedupKey;

        public ScoreResult(int score, List<Reason> reasons, String dedupKey) {
            this.score = score;
            this.reasons = List.copyOf(reasons);
            this.dedupKey = dedupKey;
        }
    }

    /** One contribution to the total, with a human-readable label. */
    public static final class Reason {
        public final String label;
        public final int delta;

        public Reason(String label, int delta) {
            this.label = label;
            this.delta = delta;
        }

        @Override
        public String toString() {
            return (delta >= 0 ? "+" : "") + delta + "  " + label;
        }
    }

    /** Pure DTO carrying the request facts that the scorer needs. */
    public static final class ParsedRequest {
        public final String method;
        public final String host;
        public final String path;
        public final String query;
        /** Header names must be lowercased by the caller. */
        public final Map<String, String> headers;
        public final int contentLength;
        public final boolean isHttp2;

        public ParsedRequest(String method, String host, String path, String query,
                             Map<String, String> headers, int contentLength, boolean isHttp2) {
            this.method = method;
            this.host = host;
            this.path = path;
            this.query = query;
            this.headers = headers;
            this.contentLength = contentLength;
            this.isHttp2 = isHttp2;
        }
    }

    /** Pure DTO carrying the response facts that the scorer needs. */
    public static final class ParsedResponse {
        public final int status;
        /** Header names must be lowercased by the caller. {@code 0} = no response captured. */
        public final Map<String, String> headers;

        public ParsedResponse(int status, Map<String, String> headers) {
            this.status = status;
            this.headers = headers;
        }
    }
}
