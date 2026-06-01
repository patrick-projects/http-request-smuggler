# HTTP Request Smuggler

> **Fork note:** Based on [PortSwigger's HTTP Request Smuggler](https://github.com/PortSwigger/http-request-smuggler). This tree adds a **Desync Agent** (context menu: *Diagnose / replicate desync*) for confirming CL.0 and related findings with editable PoCs, single-connection tests (7 attempts), auto-sweep, response panes on attack/follow-up tabs, HTTP/2 confirmation, optional Ollama analysis, and a Python spray PoC.

This Burp Suite extension automatically detects and exploits [HTTP Request Smuggling](https://portswigger.net/web-security/request-smuggling) vulnerabilities using advanced desynchronization techniques developed by PortSwigger researcher James Kettle. It supports comprehensive scanning for HTTP/1.1 and HTTP/2-downgrade desync vulnerabilities, client-side desyncs, and connection state attacks.

Version 3.0 landed in 2025 and adds parser discrepancy detection, which bypasses widespread desync defences and makes it significantly more effective. For further information on this, refer to the whitepaper [HTTP/1.1 Must Die: The Desync Endgame](https://portswigger.net/research/http1-must-die).

It's fully compatible with Burp Suite DAST, Professional, and Community editions. Pro and Community editions have a "research mode" for exploring novel techniques, and the DAST integration is useful if you want recurring scans to flag novel threats as soon as they're released.

### Features
- Detection based on root-cause detection of underlying parsing discrepancies, which is significantly more reliable and resistant to target-specific quirks.
- Many permutation techniques for bypassing different server configurations
- HTTP/1.1 CL.TE and TE.CL desync detection with timeout-based confirmation
- HTTP/2 request smuggling including tunneling and header injection attacks
- Client-side desync detection for browser-powered attacks
- Header smuggling and removal vulnerability detection
- Connection state manipulation and pause-based desync techniques
- Automated exploit generation with Turbo Intruder integration
- False positive reduction through multiple validation techniques


### Install
The easiest way to install this is in Burp Suite, via `Extender -> BApp Store`.

If you prefer to load the jar manually, in Burp Suite (community or pro), use `Extender -> Extensions -> Add` to load `build/libs/desynchronize-all.jar`.

### Compile

#### Requirements
- JDK 21 (the Gradle build is pinned to Java 21 via the toolchain).
- The PortSwigger [bulkScan framework](https://github.com/PortSwigger/bulk-scan) packaged as `bulkScan-all.jar`.
- [Turbo Intruder](https://github.com/PortSwigger/turbo-intruder) packaged as `turbo-intruder.jar` or `turbo-intruder-all.jar`.

Both JARs must live at the **root of this source tree** before building. The Gradle build runs a `checkLocalDependencies` task that prints a clear error if either is missing.

#### Build the BApp fat JAR
Linux: `./gradlew fatJar`

Windows: `gradlew.bat fatJar`

Grab the output from `build/libs/desynchronize-all.jar`. The filename is kept in lockstep with the `EntryPoint` field of [BappManifest.bmf](./BappManifest.bmf); a unit test enforces this.

### Tests

The project ships a small, self-contained JUnit 5 suite under [`src/test/java`](./src/test/java) that does not depend on Burp or Turbo Intruder at runtime. The suite covers:

- The Turbo Intruder Python templates packaged under [`resources/`](./resources) are present, non-empty, and contain the entry points that [SuggestAttack](./src/burp/SuggestAttack.java) relies on.
- The BApp manifest, Gradle archive name, and `BurpExtender.version` stay in lockstep across releases.

Run the suite with:

```
./gradlew test
```

This works **without** the PortSwigger dependency JARs above because the test source set is configured to be independent of the main source set. Adding tests that exercise main-source classes will require both `bulkScan-all.jar` and Turbo Intruder to be present locally.

### Continuous integration

GitHub Actions workflow [`.github/workflows/ci.yml`](./.github/workflows/ci.yml) runs on every push and pull request and:

1. Validates the Gradle wrapper signature.
2. Runs the JUnit suite on JDK 21 (does not need the closed-source dependency JARs).
3. Optionally builds the fat JAR via `workflow_dispatch` with `run-fatjar=true` — that job is skipped by default because the BulkScan / Turbo Intruder JARs are not redistributable through this repository and must be staged into the workspace by a prior step.

### Use
Right click on a request and click `Launch Smuggle probe`, then watch the Organizer and extension's output pane under `Extender->Extensions->HTTP Request Smuggler`

If you're using Burp Pro, any findings will also be reported as scan issues.

If you right click on a request that uses chunked encoding, you'll see another option marked `Launch Smuggle attack`. This will open a Turbo Intruder window in which you can try out various attacks by editing the `prefix` variable.

For more advanced use watch the [video](https://portswigger.net/blog/http-desync-attacks).

### Practice

We've released a collection of [free online labs to practise against](https://portswigger.net/web-security/request-smuggling). Here's how to use the tool to solve the first lab - [HTTP request smuggling, basic CL.TE vulnerability](https://portswigger.net/web-security/request-smuggling/lab-basic-cl-te):

1. Use the Extender->BApp store tab to install the 'HTTP Request Smuggler' extension.
2. Load the lab homepage, find the request in the proxy history, right click and select 'Launch smuggle probe', then click 'OK'.
3. Wait for the probe to complete, indicated by 'Completed 1 of 1' appearing in the extension's output tab.
4. If you're using Burp Suite Pro, find the reported vulnerability in the dashboard and open the first attached request.
5. If you're using Burp Suite Community, copy the request from the output tab and paste it into the repeater, then complete the 'Target' details on the top right.
6. Right click on the request and select 'Smuggle attack (CL.TE)'.
7. Change the value of the 'prefix' variable to 'G', then click 'Attack' and confirm that one response says 'Unrecognised method GPOST'.

By changing the 'prefix' variable in step 7, you can solve all the labs and virtually every real-world scenario.
