package burp;

import burp.api.montoya.http.message.HttpRequestResponse;

/**
 * One scored proxy-history or site-map entry, paired with the Burp
 * {@link HttpRequestResponse} that originated it so the Tab can route it
 * back into Repeater / Organizer / smuggling scans on demand.
 *
 * <p>Holds extracted display fields directly so the table model can render
 * them without re-parsing the request bytes on every paint.</p>
 */
public final class SmuggleCandidate {
    public final HttpRequestResponse requestResponse;
    public final SmuggleTargetScorer.ScoreResult score;
    public final String method;
    public final String host;
    public final String path;
    public final int status;
    public volatile String actionStatus;

    public SmuggleCandidate(HttpRequestResponse requestResponse,
                            SmuggleTargetScorer.ScoreResult score,
                            String method,
                            String host,
                            String path,
                            int status) {
        this.requestResponse = requestResponse;
        this.score = score;
        this.method = method;
        this.host = host;
        this.path = path;
        this.status = status;
        this.actionStatus = "Ready";
    }
}
