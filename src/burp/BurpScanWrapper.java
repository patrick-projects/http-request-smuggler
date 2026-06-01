package burp;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.scancheck.ActiveScanCheck;

import java.util.HashSet;
import java.util.Set;

// todo make generic & move to bulkScan
public class BurpScanWrapper implements ActiveScanCheck {

    /**
     * Internal scan name used when constructing a {@link ParserDiscrepancyScan}
     * for Burp's active-scan integration. Keep this distinct from the menu-driven
     * scan name registered in {@link BurpExtender#registerExtenderCallbacks} so
     * that scan settings registered for each path do not collide.
     */
    private static final String DAST_SCAN_NAME = "Parser discrepancy DAST scan";

    private final Set<String> seenTargets = new HashSet<>();

    @Override
    public String checkName() {
        return BurpExtender.name;
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse httpRequestResponse, AuditInsertionPoint auditInsertionPoint, Http http) {

        // todo maybe just use server header
        String key = httpRequestResponse.httpService().toString() + new MontoyaRequestResponse(httpRequestResponse).server();
        if (!seenTargets.add(key)) {
            return null;
        }

        ParserDiscrepancyScan scan = new ParserDiscrepancyScan(DAST_SCAN_NAME);
        scan.insideScanner = true;
        Report report = scan.doScan(httpRequestResponse.request());
        if (report == null) {
            return null;
        }
        return AuditResult.auditResult(report.getIssue());
    }
}
