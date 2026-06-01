package burp;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.function.Consumer;

/**
 * Minimal client for a local <a href="https://ollama.com">Ollama</a> server.
 *
 * <p>Uses only the JDK's built-in HTTP client and hand-rolled JSON handling so the
 * extension picks up no extra dependencies. Talks to the non-streaming
 * {@code /api/chat} endpoint and returns the assistant message content with any
 * {@code <think>...</think>} reasoning trace stripped.</p>
 */
final class OllamaClient {

    private OllamaClient() {
    }

    /**
     * Streaming chat: posts with {@code "stream":true} and invokes {@code onToken}
     * for each content fragment as it arrives (including any {@code <think>}
     * reasoning, so the operator can watch the model work). Returns the full raw
     * concatenated content once the stream completes.
     */
    static String chatStream(String baseUrl, String model, String system, String user,
                             int timeoutSeconds, Consumer<String> onToken) throws Exception {
        String endpoint = normalizeBase(baseUrl) + "/api/chat";
        String payload = "{"
                + "\"model\":" + jsonString(model) + ","
                + "\"stream\":true,"
                + "\"messages\":["
                + "{\"role\":\"system\",\"content\":" + jsonString(system) + "},"
                + "{\"role\":\"user\",\"content\":" + jsonString(user) + "}"
                + "]}";

        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        java.net.http.HttpRequest request = java.net.http.HttpRequest.newBuilder(URI.create(endpoint))
                .timeout(Duration.ofSeconds(Math.max(15, timeoutSeconds)))
                .header("Content-Type", "application/json")
                .POST(java.net.http.HttpRequest.BodyPublishers.ofString(payload, StandardCharsets.UTF_8))
                .build();

        HttpResponse<InputStream> response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
        if (response.statusCode() / 100 != 2) {
            String body;
            try (InputStream in = response.body()) {
                body = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            }
            throw new RuntimeException("Ollama returned HTTP " + response.statusCode() + ": "
                    + truncate(body, 600));
        }

        StringBuilder full = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(response.body(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.trim().isEmpty()) {
                    continue;
                }
                String error = extractStringField(line, "error");
                if (error != null) {
                    throw new RuntimeException("Ollama error: " + error);
                }
                String piece = extractStringField(line, "content");
                if (piece != null && !piece.isEmpty()) {
                    full.append(piece);
                    if (onToken != null) {
                        onToken.accept(piece);
                    }
                }
            }
        }
        return full.toString();
    }

    static String chat(String baseUrl, String model, String system, String user, int timeoutSeconds)
            throws Exception {
        String endpoint = normalizeBase(baseUrl) + "/api/chat";
        String payload = "{"
                + "\"model\":" + jsonString(model) + ","
                + "\"stream\":false,"
                + "\"messages\":["
                + "{\"role\":\"system\",\"content\":" + jsonString(system) + "},"
                + "{\"role\":\"user\",\"content\":" + jsonString(user) + "}"
                + "]}";

        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        java.net.http.HttpRequest request = java.net.http.HttpRequest.newBuilder(URI.create(endpoint))
                .timeout(Duration.ofSeconds(Math.max(15, timeoutSeconds)))
                .header("Content-Type", "application/json")
                .POST(java.net.http.HttpRequest.BodyPublishers.ofString(payload, StandardCharsets.UTF_8))
                .build();

        HttpResponse<String> response = client.send(request,
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        String body = response.body();
        if (response.statusCode() / 100 != 2) {
            throw new RuntimeException("Ollama returned HTTP " + response.statusCode() + ": "
                    + truncate(body, 600));
        }

        String content = extractStringField(body, "content");
        if (content == null) {
            // Fall back to the /api/generate response shape just in case.
            content = extractStringField(body, "response");
        }
        if (content == null) {
            throw new RuntimeException("Could not parse Ollama response: " + truncate(body, 600));
        }
        return stripThink(content).trim();
    }

    private static String normalizeBase(String baseUrl) {
        String url = (baseUrl == null || baseUrl.trim().isEmpty())
                ? "http://localhost:11434" : baseUrl.trim();
        while (url.endsWith("/")) {
            url = url.substring(0, url.length() - 1);
        }
        return url;
    }

    private static String stripThink(String s) {
        if (s == null) {
            return "";
        }
        // Remove reasoning traces emitted by thinking models (e.g. qwen3).
        String cleaned = s.replaceAll("(?is)<think>.*?</think>", "");
        // Handle an unterminated <think> block defensively.
        int open = cleaned.toLowerCase().indexOf("<think>");
        if (open >= 0 && cleaned.toLowerCase().indexOf("</think>") < 0) {
            cleaned = cleaned.substring(0, open);
        }
        return cleaned;
    }

    /** Encodes a Java string as a JSON string literal (including surrounding quotes). */
    private static String jsonString(String s) {
        if (s == null) {
            return "\"\"";
        }
        StringBuilder sb = new StringBuilder(s.length() + 16);
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':
                    sb.append("\\\"");
                    break;
                case '\\':
                    sb.append("\\\\");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                case '\b':
                    sb.append("\\b");
                    break;
                case '\f':
                    sb.append("\\f");
                    break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
        return sb.toString();
    }

    /**
     * Extracts the first JSON string value for {@code "key"}, decoding standard
     * JSON escape sequences. Sufficient for Ollama's flat response objects where
     * the key of interest ("content"/"response") appears once.
     */
    private static String extractStringField(String json, String key) {
        if (json == null) {
            return null;
        }
        String needle = "\"" + key + "\"";
        int idx = json.indexOf(needle);
        if (idx < 0) {
            return null;
        }
        int i = idx + needle.length();
        // Skip whitespace and the ':' separator.
        while (i < json.length() && (json.charAt(i) == ' ' || json.charAt(i) == '\t'
                || json.charAt(i) == '\n' || json.charAt(i) == '\r')) {
            i++;
        }
        if (i >= json.length() || json.charAt(i) != ':') {
            return null;
        }
        i++;
        while (i < json.length() && (json.charAt(i) == ' ' || json.charAt(i) == '\t'
                || json.charAt(i) == '\n' || json.charAt(i) == '\r')) {
            i++;
        }
        if (i >= json.length() || json.charAt(i) != '"') {
            return null;
        }
        i++;
        StringBuilder sb = new StringBuilder();
        while (i < json.length()) {
            char c = json.charAt(i);
            if (c == '\\') {
                if (i + 1 >= json.length()) {
                    break;
                }
                char next = json.charAt(i + 1);
                switch (next) {
                    case '"':
                        sb.append('"');
                        break;
                    case '\\':
                        sb.append('\\');
                        break;
                    case '/':
                        sb.append('/');
                        break;
                    case 'n':
                        sb.append('\n');
                        break;
                    case 'r':
                        sb.append('\r');
                        break;
                    case 't':
                        sb.append('\t');
                        break;
                    case 'b':
                        sb.append('\b');
                        break;
                    case 'f':
                        sb.append('\f');
                        break;
                    case 'u':
                        if (i + 5 < json.length()) {
                            try {
                                sb.append((char) Integer.parseInt(json.substring(i + 2, i + 6), 16));
                            } catch (NumberFormatException ignored) {
                                // leave as-is
                            }
                            i += 4;
                        }
                        break;
                    default:
                        sb.append(next);
                }
                i += 2;
            } else if (c == '"') {
                return sb.toString();
            } else {
                sb.append(c);
                i++;
            }
        }
        return sb.toString();
    }

    private static String truncate(String s, int max) {
        if (s == null) {
            return "";
        }
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }
}
