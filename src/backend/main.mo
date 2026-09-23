import Time "mo:base/Time";
import Array "mo:base/Array";
import Text "mo:base/Text";
import Blob "mo:base/Blob";


actor RelayBackend {

    // --- Types ---
    public type FirewallMode = { #Off; #Medium; #On };
    public type ThreatEvent = {
        timestamp : Int;
        threatType : Text;
        severity : Text;
        snippet : Text;
    };
    public type SystemStats = {
        mode : Text;
        totalProcessed : Nat;
        totalBlocked : Nat;
        activeQueueLength : Nat;
    };

    // HTTP Types for iOS Shortcut / Mac Native Integration
    public type HeaderField = (Text, Text);
    public type HttpRequest = { method : Text; url : Text; headers : [HeaderField]; body : Blob };
    public type HttpResponse = { status_code : Nat16; headers : [HeaderField]; body : Blob; upgrade : ?Bool };

    // --- State Variables ---
    private var currentMode : FirewallMode = #Medium;
    private var totalProcessed : Nat = 0;
    private var totalBlocked : Nat = 0;
    
    // Communication Queues
    private var pendingPrompt : Text = ""; 
    private var latestResponse : Text = "";
    private var responseAvailable : Bool = false;

    // Circular Threat Buffer (Max 10)
    private var threatLog : [var ?ThreatEvent] = [var null, null, null, null, null, null, null, null, null, null];
    private var logPointer : Nat = 0;

    // Security Key
    private let _API_KEY = "Bearer cyber-dolphin-2026"; 

    // --- Internal Logic ---
    private func previewText(t : Text, maxLen : Nat) : Text {
        if (t.size() <= maxLen) return t;
        var result = "";
        var count : Nat = 0;
        for (c in t.chars()) {
            if (count >= maxLen) {
                return result;
            };
            result #= Text.fromChar(c);
            count += 1;
        };
        return result;
    };

    private func logThreat(threatType : Text, severity : Text, snippet : Text) {
        threatLog[logPointer] := ?{ timestamp = Time.now(); threatType; severity; snippet };
        logPointer := (logPointer + 1) % 10;
        totalBlocked += 1;
    };

    private func scanForThreats(payload : Text) : ?Text {
        let lower = Text.toLowercase(payload);
        if (Text.contains(lower, #text "ignore previous instructions") or Text.contains(lower, #text "system override")) {
            return ?"Prompt Injection Attempt";
        };
        if (Text.size(payload) > 8000) {
            return ?"Context Overflow";
        };
        return null;
    };

    // --- UI Dashboard Endpoints (Candid) ---
    public query func getStats() : async SystemStats {
        let modeText = switch(currentMode) { case(#Off) "OFF (Uncensored)"; case(#Medium) "MEDIUM (Guarded)"; case(#On) "ON (Locked)"; };
        return { mode = modeText; totalProcessed; totalBlocked; activeQueueLength = if (pendingPrompt == "") 0 else 1 };
    };

    public query func getPendingPrompt() : async Text {
        pendingPrompt
    };

    public shared func saveResult(result : Text) : async Text {
        latestResponse := result;
        responseAvailable := true;
        pendingPrompt := "";
        "Result Saved"
    };

    public shared func takeLatestResponse() : async Text {
        let response = if (responseAvailable) latestResponse else "";
        latestResponse := "";
        responseAvailable := false;
        response
    };

    public shared func setMode(newModeText : Text) : async Text {
        if (newModeText == "Off") { currentMode := #Off; }
        else if (newModeText == "On") { currentMode := #On; }
        else { currentMode := #Medium; };
        return "Mode updated.";
    };

    public query func getThreats() : async [ThreatEvent] {
        var results : [ThreatEvent] = [];
        for (item in threatLog.vals()) {
            switch (item) {
                case (?event) { results := Array.append<ThreatEvent>(results, [event]); };
                case (null) {};
            };
        };
        return results;
    };

    // --- HTTP Gateway (For Apple Shortcuts & Mac Daemon) ---
    public query func http_request(req : HttpRequest) : async HttpResponse {
        // Upgrade POST requests to update calls so state changes persist
        if (req.method == "POST") {
            return { status_code = 200; headers = []; body = Blob.fromArray([]); upgrade = ?true };
        };
        
        // GET /api/queue -> Mac Daemon fetches the prompt
        if (req.method == "GET" and req.url == "/api/queue") {
            return {
                status_code = 200;
                headers = [("Content-Type", "text/plain"), ("Cache-Control", "no-store, no-cache, must-revalidate"), ("Pragma", "no-cache")];
                body = Text.encodeUtf8(pendingPrompt);
                upgrade = ?false;
            };
        };

        // GET /api/response -> Upgrade to update call so state can be cleared upon read
        if (req.method == "GET" and req.url == "/api/response") {
            return {
                status_code = 200;
                headers = [];
                body = Blob.fromArray([]);
                upgrade = ?true;
            };
        };

        return { status_code = 404; headers = []; body = Text.encodeUtf8("Not Found"); upgrade = ?false };
    };

    public shared func http_request_update(req : HttpRequest) : async HttpResponse {
        // Handle GET /api/response update execution (Auto-clear on read)
        if (req.method == "GET" and req.url == "/api/response") {
            let resp = if (responseAvailable) latestResponse else "";
            
            // Clear buffer immediately after reading to stop shortcut loop
            latestResponse := "";
            responseAvailable := false;

            return {
                status_code = 200;
                headers = [("Content-Type", "text/plain"), ("Cache-Control", "no-store, no-cache, must-revalidate"), ("Pragma", "no-cache")];
                body = Text.encodeUtf8(resp);
                upgrade = ?false;
            };
        };

        let decodedBody = Text.decodeUtf8(req.body);

        switch (decodedBody) {
            case (?textBody) {
                // POST /api/prompt -> iOS Shortcut sends prompt
                if (req.url == "/api/prompt") {
                    totalProcessed += 1;

                    switch (currentMode) {
                        case (#On) {
                            logThreat("Remote Execution Lockout", "HIGH", previewText(textBody, 40));
                            return { status_code = 403; headers = []; body = Text.encodeUtf8("PC is Locked."); upgrade = ?false };
                        };
                        case (#Medium) {
                            switch (scanForThreats(textBody)) {
                                case (?threat) {
                                    logThreat(threat, "CRITICAL", previewText(textBody, 40));
                                    return { status_code = 406; headers = []; body = Text.encodeUtf8("Threat Blocked."); upgrade = ?false };
                                };
                                case (null) { pendingPrompt := textBody; latestResponse := ""; };
                            };
                        };
                        case (#Off) { pendingPrompt := textBody; latestResponse := ""; };
                    };
                    return { status_code = 200; headers = []; body = Text.encodeUtf8("Queued"); upgrade = ?false };
                };

                // POST /api/result -> Mac Daemon posts the output
                if (req.url == "/api/result") {
                    latestResponse := textBody;
                    responseAvailable := true;
                    pendingPrompt := ""; // Clear queue
                    return { status_code = 200; headers = []; body = Text.encodeUtf8("Result Saved"); upgrade = ?false };
                };

                if (req.url == "/api/response/ack") {
                    latestResponse := "";
                    responseAvailable := false;
                    return { status_code = 200; headers = []; body = Text.encodeUtf8("Response Acknowledged"); upgrade = ?false };
                };
            };
            case (null) {
                return { status_code = 400; headers = []; body = Text.encodeUtf8("Invalid UTF-8 payload"); upgrade = ?false };
            };
        };

        return { status_code = 404; headers = []; body = Text.encodeUtf8("Not Found"); upgrade = ?false };
    };
};
