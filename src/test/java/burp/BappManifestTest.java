package burp;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Validates that the BApp Store manifest and packaging metadata agree with
 * each other and with the version constant baked into {@code BurpExtender}.
 *
 * <p>This catches the "version string duplication" drift identified in the
 * project quality assessment: {@code BurpExtender.version} and
 * {@code BappManifest.bmf:ScreenVersion} must stay in lockstep across
 * releases.</p>
 */
class BappManifestTest {

    private static final Path MANIFEST_PATH = Path.of("BappManifest.bmf");
    private static final Path BURP_EXTENDER_PATH = Path.of("src", "burp", "BurpExtender.java");
    private static final Path BUILD_GRADLE_PATH = Path.of("build.gradle");

    @Test
    void manifestIsParseable() throws IOException {
        Map<String, String> manifest = readManifest();
        assertNotNull(manifest.get("Name"));
        assertNotNull(manifest.get("Uuid"));
        assertNotNull(manifest.get("ScreenVersion"));
        assertNotNull(manifest.get("EntryPoint"));
    }

    @Test
    void manifestEntryPointMatchesArchivesName() throws IOException {
        Map<String, String> manifest = readManifest();
        String entryPoint = manifest.get("EntryPoint");
        String buildContent = Files.readString(BUILD_GRADLE_PATH, StandardCharsets.UTF_8);

        Matcher matcher = Pattern.compile("archivesName\\s*=\\s*['\"]([^'\"]+)['\"]")
                .matcher(buildContent);
        assertTrue(matcher.find(),
                "build.gradle does not declare an archivesName; the fat JAR filename "
                        + "may drift from BappManifest.bmf:EntryPoint");
        String archivesName = matcher.group(1);

        assertEquals(archivesName + ".jar", entryPoint,
                "BappManifest.bmf:EntryPoint must match the Gradle archivesName + .jar");
    }

    @Test
    void manifestScreenVersionMatchesBurpExtenderVersion() throws IOException {
        Map<String, String> manifest = readManifest();
        String manifestVersion = manifest.get("ScreenVersion");

        String burpExtender = Files.readString(BURP_EXTENDER_PATH, StandardCharsets.UTF_8);
        Matcher matcher = Pattern.compile("String\\s+version\\s*=\\s*\"([^\"]+)\"")
                .matcher(burpExtender);
        assertTrue(matcher.find(),
                "BurpExtender.java does not declare a version string in the expected format");
        String sourceVersion = matcher.group(1);

        assertEquals(manifestVersion, sourceVersion,
                "BappManifest.bmf:ScreenVersion must match the version constant in BurpExtender.java; "
                        + "bump both in lockstep on release");
    }

    @Test
    void manifestBuildCommandMatchesGradleTask() throws IOException {
        Map<String, String> manifest = readManifest();
        String buildCommand = manifest.get("BuildCommand");
        assertNotNull(buildCommand);
        assertTrue(buildCommand.contains("fatJar"),
                "BappManifest.bmf:BuildCommand should invoke the fatJar task; got: " + buildCommand);

        String buildContent = Files.readString(BUILD_GRADLE_PATH, StandardCharsets.UTF_8);
        assertTrue(buildContent.contains("'fatJar'") || buildContent.contains("\"fatJar\""),
                "build.gradle no longer defines a fatJar task; BappManifest.bmf will fail to build");
    }

    private Map<String, String> readManifest() throws IOException {
        Map<String, String> result = new HashMap<>();
        for (String line : Files.readAllLines(MANIFEST_PATH, StandardCharsets.UTF_8)) {
            int colonIdx = line.indexOf(':');
            if (colonIdx <= 0) {
                continue;
            }
            String key = line.substring(0, colonIdx).trim();
            String value = line.substring(colonIdx + 1).trim();
            result.put(key, value);
        }
        return result;
    }
}
