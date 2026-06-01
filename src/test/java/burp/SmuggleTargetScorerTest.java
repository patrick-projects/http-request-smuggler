package burp;

import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link SmuggleTargetScorer}. These run in the independent
 * test source set declared in {@code build.gradle} and intentionally avoid
 * any Burp / PortSwigger imports.
 *
 * <p>The scorer is the part of the target picker that decides which HTTP
 * requests are worth a smuggling probe; if any of these rules drift the
 * picker will silently start surfacing the wrong requests. The tests pin
 * each rule individually so a regression points at the exact signal.</p>
 */
class SmuggleTargetScorerTest {

    @Test
    void postWithFormBodyOnDynamicEndpointScoresAboveStaticAsset() {
        SmuggleTargetScorer.ScoreResult dynamic = score(
                "POST", "shop.example", "/api/login", "",
                headers("content-type", "application/x-www-form-urlencoded",
                        "content-length", "42"),
                42, false,
                200, headers("server", "nginx", "set-cookie", "JSESSIONID=abc"));

        SmuggleTargetScorer.ScoreResult staticAsset = score(
                "GET", "shop.example", "/static/app.css", "",
                Collections.emptyMap(), 0, false,
                200, Collections.emptyMap());

        assertTrue(dynamic.score > staticAsset.score,
                "POST /api/login should rank above GET /static/app.css; got "
                        + dynamic.score + " vs " + staticAsset.score);
        assertTrue(dynamic.score >= 30 + 20 + 10 + 5,
                "POST + Content-Length + parseable CT + backend signals should sum to >= 65; got "
                        + dynamic.score);
        assertTrue(staticAsset.score <= -30,
                "Static asset should be deep in the negatives from the -50 penalty; got " + staticAsset.score);
    }

    @Test
    void httpTwoTargetGetsBonus() {
        SmuggleTargetScorer.ScoreResult withH2 = score(
                "GET", "example.com", "/", "",
                Collections.emptyMap(), 0, true,
                200, Collections.emptyMap());
        SmuggleTargetScorer.ScoreResult noH2 = score(
                "GET", "example.com", "/", "",
                Collections.emptyMap(), 0, false,
                200, Collections.emptyMap());

        assertEquals(10, withH2.score - noH2.score,
                "HTTP/2 capability should add exactly +10");
    }

    @Test
    void cdnMarkersGiveBonusAcrossAllProviders() {
        for (String[] header : new String[][]{
                {"cf-ray", "12345"},
                {"x-amz-cf-id", "abc"},
                {"x-fastly-request-id", "abc"},
                {"x-served-by", "cache-bos"},
                {"server", "AkamaiGHost"},
                {"server", "cloudflare"},
                {"server", "CloudFront"}}) {
            SmuggleTargetScorer.ScoreResult withCdn = score(
                    "GET", "h.example", "/", "",
                    Collections.emptyMap(), 0, false,
                    200, headers(header[0], header[1]));
            SmuggleTargetScorer.ScoreResult plain = score(
                    "GET", "h.example", "/", "",
                    Collections.emptyMap(), 0, false,
                    200, Collections.emptyMap());
            assertTrue(withCdn.score >= plain.score + 15,
                    "CDN signal " + header[0] + ":" + header[1] + " should grant >= +15 bonus; got "
                            + (withCdn.score - plain.score));
        }
    }

    @Test
    void noResponseCapturedSinksTheCandidateDeeply() {
        SmuggleTargetScorer.ScoreResult missing = score(
                "POST", "x", "/api", "",
                headers("content-type", "application/json", "content-length", "5"),
                5, true,
                0, Collections.emptyMap());
        SmuggleTargetScorer.ScoreResult present = score(
                "POST", "x", "/api", "",
                headers("content-type", "application/json", "content-length", "5"),
                5, true,
                200, Collections.emptyMap());

        assertTrue(missing.score < present.score,
                "A missing response must score below an otherwise-equivalent live one");
        assertEquals(100, present.score - missing.score,
                "Missing response should cost exactly -100 vs a captured 200; got "
                        + (present.score - missing.score));
    }

    @Test
    void fourOhFourPenalizesButFourOhOneDoesNot() {
        SmuggleTargetScorer.ScoreResult fourOhFour = score(
                "POST", "x", "/api", "",
                headers("content-length", "1"), 1, false,
                404, Collections.emptyMap());
        SmuggleTargetScorer.ScoreResult fourOhOne = score(
                "POST", "x", "/api", "",
                headers("content-length", "1"), 1, false,
                401, Collections.emptyMap());

        assertEquals(10, fourOhOne.score - fourOhFour.score,
                "401 should be neutral and 404 should cost -10; expected a 10 point gap, got "
                        + (fourOhOne.score - fourOhFour.score));
    }

    @Test
    void serverErrorIsPenalizedLessThanClientError() {
        SmuggleTargetScorer.ScoreResult five = score(
                "GET", "x", "/", "",
                Collections.emptyMap(), 0, false,
                502, Collections.emptyMap());
        SmuggleTargetScorer.ScoreResult fourTen = score(
                "GET", "x", "/", "",
                Collections.emptyMap(), 0, false,
                410, Collections.emptyMap());

        assertTrue(five.score > fourTen.score,
                "5xx (-5) should outrank a generic 4xx (-10); got 502="
                        + five.score + ", 410=" + fourTen.score);
    }

    @Test
    void backendProcessingSignalsGiveExpectedBonus() {
        SmuggleTargetScorer.ScoreResult quiet = score(
                "GET", "x", "/health", "",
                Collections.emptyMap(), 0, false,
                200, Collections.emptyMap());
        SmuggleTargetScorer.ScoreResult chatty = score(
                "GET", "x", "/health", "",
                Collections.emptyMap(), 0, false,
                200, headers("set-cookie", "id=1"));

        assertEquals(5, chatty.score - quiet.score,
                "Set-Cookie alone should grant +5; got " + (chatty.score - quiet.score));
    }

    @Test
    void parseableContentTypeAddsBonus() {
        SmuggleTargetScorer.ScoreResult json = score(
                "POST", "x", "/api", "",
                headers("content-type", "application/json"), 0, false,
                200, Collections.emptyMap());
        SmuggleTargetScorer.ScoreResult opaque = score(
                "POST", "x", "/api", "",
                headers("content-type", "application/octet-stream"), 0, false,
                200, Collections.emptyMap());

        assertEquals(10, json.score - opaque.score,
                "JSON Content-Type should add +10 over opaque; got " + (json.score - opaque.score));
    }

    @Test
    void getWithQueryStringIsNotPenalizedAsStaticAsset() {
        // /foo.css?cb=1 should NOT be treated as a static asset because of the query string.
        SmuggleTargetScorer.ScoreResult queried = score(
                "GET", "x", "/foo.css", "cb=1",
                Collections.emptyMap(), 0, false,
                200, Collections.emptyMap());
        assertTrue(queried.score >= 10,
                ".css with a query string should not be sunk; got " + queried.score);

        for (SmuggleTargetScorer.Reason r : queried.reasons) {
            assertFalse(r.label.toLowerCase().contains("static"),
                    "Should not emit a 'static asset' reason when a query string is present");
        }
    }

    @Test
    void normalizePathCollapsesNumericSegments() {
        assertEquals("/users/*/orders/*", SmuggleTargetScorer.normalizePath("/users/123/orders/4567"));
        assertEquals("", SmuggleTargetScorer.normalizePath(null));
        assertEquals("/", SmuggleTargetScorer.normalizePath("/"));
    }

    @Test
    void normalizePathCollapsesUuidAndHexSegments() {
        assertEquals("/v1/sessions/*",
                SmuggleTargetScorer.normalizePath("/v1/sessions/550e8400-e29b-41d4-a716-446655440000"));
        assertEquals("/etags/*",
                SmuggleTargetScorer.normalizePath("/etags/d41d8cd98f00b204e9800998ecf8427e"));
    }

    @Test
    void normalizePathDropsQueryStringSoEquivalentRequestsDedupe() {
        assertEquals(SmuggleTargetScorer.normalizePath("/api/login"),
                SmuggleTargetScorer.normalizePath("/api/login?next=/home"));
    }

    @Test
    void dedupKeyIsHostMethodAndNormalizedPath() {
        String key1 = SmuggleTargetScorer.buildDedupKey("Shop.Example", "post", "/users/123");
        String key2 = SmuggleTargetScorer.buildDedupKey("shop.example", "POST", "/users/456");
        assertEquals(key1, key2,
                "Different numeric IDs on the same endpoint must collide into one dedup bucket");

        String different = SmuggleTargetScorer.buildDedupKey("shop.example", "GET", "/users/123");
        assertFalse(different.equals(key1),
                "Different methods on the same path must not collide");
    }

    // ---------- helpers ----------

    private static SmuggleTargetScorer.ScoreResult score(String method, String host, String path,
                                                         String query, Map<String, String> reqHeaders,
                                                         int contentLength, boolean http2,
                                                         int status, Map<String, String> respHeaders) {
        SmuggleTargetScorer.ParsedRequest req = new SmuggleTargetScorer.ParsedRequest(
                method, host, path, query, lower(reqHeaders), contentLength, http2);
        SmuggleTargetScorer.ParsedResponse resp = new SmuggleTargetScorer.ParsedResponse(status, lower(respHeaders));
        return SmuggleTargetScorer.score(req, resp);
    }

    private static Map<String, String> headers(String... kv) {
        Map<String, String> out = new HashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) {
            out.put(kv[i], kv[i + 1]);
        }
        return out;
    }

    /** The Tab adapter lowercases header names before handing them to the scorer; mirror that here. */
    private static Map<String, String> lower(Map<String, String> in) {
        Map<String, String> out = new HashMap<>(in.size());
        for (Map.Entry<String, String> e : in.entrySet()) {
            out.put(e.getKey().toLowerCase(), e.getValue());
        }
        return out;
    }
}
