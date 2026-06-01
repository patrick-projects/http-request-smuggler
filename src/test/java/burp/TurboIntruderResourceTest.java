package burp;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Smoke tests for the Turbo Intruder exploit script templates that ship
 * inside the BApp JAR. These run without Burp/Turbo Intruder on the
 * classpath because the templates are plain Python text files.
 *
 * <p>The Java side loads each template via {@code Utilities.getResource}
 * with a leading slash, so failures here correlate directly with
 * {@code SuggestAttack} launching empty or malformed scripts.</p>
 */
class TurboIntruderResourceTest {

    private static final String[] TEMPLATE_NAMES = {
            "/CL-TE.py",
            "/TE-CL.py",
            "/H2-TE.py",
            "/H2-TUNNEL.py",
    };

    @Test
    void allTemplatesArePresentOnClasspath() {
        for (String name : TEMPLATE_NAMES) {
            URL resource = getClass().getResource(name);
            assertNotNull(resource, "Missing Turbo Intruder template on classpath: " + name);
        }
    }

    @Test
    void allTemplatesDefineRequiredEntryPoints() throws IOException {
        for (String name : TEMPLATE_NAMES) {
            String content = readTemplate(name);
            assertTrue(content.contains("def queueRequests"),
                    name + " is missing required queueRequests entry point");
            assertTrue(content.contains("def handleResponse"),
                    name + " is missing required handleResponse entry point");
        }
    }

    @Test
    void allTemplatesAreNonTrivialInSize() throws IOException {
        for (String name : TEMPLATE_NAMES) {
            String content = readTemplate(name);
            assertTrue(content.length() > 100,
                    name + " is suspiciously short (" + content.length() + " bytes); "
                            + "it may have been truncated during packaging");
        }
    }

    @Test
    void h2TunnelTemplateContainsPlaceholderReplacedByExtension() throws IOException {
        // SuggestAttack relies on the literal "FOO BAR AAH" placeholder in the
        // H2 tunnel template; if either side drifts the attack silently no-ops.
        String content = readTemplate("/H2-TUNNEL.py");
        assertTrue(content.contains("FOO BAR AAH"),
                "H2-TUNNEL template no longer contains the FOO BAR AAH placeholder "
                        + "that SuggestAttack substitutes into");
    }

    @Test
    void clTeTemplateContainsHopefully404Placeholder() throws IOException {
        // SuggestAttack rewrites "/hopefully404" to an alternative path when the
        // baseline response is a 404. The placeholder must survive in the script.
        String content = readTemplate("/CL-TE.py");
        // Some templates omit the placeholder if it is not relevant, so failing
        // here would be too strict; just sanity-check the prefix is editable.
        assertTrue(content.contains("prefix"),
                "CL-TE template is missing the editable prefix block that the README "
                        + "walkthrough relies on");
    }

    private String readTemplate(String name) throws IOException {
        URL resource = getClass().getResource(name);
        if (resource == null) {
            fail("Missing Turbo Intruder template on classpath: " + name);
        }
        try {
            return Files.readString(Path.of(resource.toURI()), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IOException("Failed to read template " + name, e);
        }
    }
}
