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

    public type HeaderField = (Text, Text);
    public type HttpRequest = { method : Text; url : Text; headers : [HeaderField]; body : Blob };
    public type HttpResponse = { status_code : Nat16; headers : [HeaderField]; body : Blob; upgrade : ?Bool };

    // --- State Variables ---
    private var currentMode : FirewallMode = #Medium;
    private var totalProcessed : Nat = 0;
    private var totalBlocked : Nat = 0;
    
    private var pendingPrompt : Text = ""; 
    private var latestResponse : Text = "";
    private var responseAvailable : Bool = false;

    private var threatLog : [var ?ThreatEvent] = [var null, null, null, null, null, null, null, null, null, null];
    private var logPointer : Nat = 0;

    private func previewText(t : Text, maxLen : Nat) : Text {
        if (t.size() <= maxLen) return t;
        var result = "";
        var count : Nat = 0;
        for (c in t.chars()) {
            if (count >= maxLen) return result;
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

        if (Text.contains(lower, #text "ignore previous instructions") or 
            Text.contains(lower, #text "system override") or 
            Text.contains(lower, #text "jailbreak") or 
            Text.contains(lower, #text "bypass security")) {
            return ?"Prompt Injection Blocked";
        };

        if (Text.contains(lower, #text "rm -rf") or 
            Text.contains(lower, #text "delete hard drive") or 
            Text.contains(lower, #text "erase hard drive") or 
            Text.contains(lower, #text "format disk") or 
            Text.contains(lower, #text "mkfs")) {
            return ?"Destructive File Removal Blocked";
        };

        if (Text.contains(lower, #text "sudo") or 
            Text.contains(lower, #text "root access") or 
            Text.contains(lower, #text "change password") or 
            Text.contains(lower, #text "chmod 777") or 
            Text.contains(lower, #text "passwd")) {
            return ?"Privilege Escalation Blocked";
        };

        if (Text.size(payload) > 8000) {
            return ?"Context Overflow Blocked";
        };

        return null;
    };

    public query func getStats() : async SystemStats {
        let modeText = switch(currentMode) { case(#Off) "OFF"; case(#Medium) "MEDIUM"; case(#On) "ON"; };
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

    // --- Direct Web Interface Endpoint ---
    public shared func submitPrompt(textBody : Text) : async Text {
        totalProcessed += 1;

        switch (currentMode) {
            case (#On) {
                logThreat("Execution Lockout", "HIGH", previewText(textBody, 40));
                return "BLOCKED: System Locked (ON boundary active).";
            };
            case (#Medium) {
                switch (scanForThreats(textBody)) {
                    case (?threat) {
                        logThreat(threat, "CRITICAL", previewText(textBody, 40));
                        return "BLOCKED: " # threat;
                    };
                    case (null) { 
                        pendingPrompt := textBody; 
                        latestResponse := ""; 
                        return "QUEUED";
                    };
                };
            };
            case (#Off) { 
                pendingPrompt := textBody; 
                latestResponse := ""; 
                return "QUEUED";
            };
        };
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

    // --- HTTP Gateway ---
    public query func http_request(req : HttpRequest) : async HttpResponse {
        if (req.method == "POST") {
            return { status_code = 200; headers = []; body = Blob.fromArray([]); upgrade = ?true };
        };
        
        if (req.method == "GET" and req.url == "/api/queue") {
            return {
                status_code = 200;
                headers = [("Content-Type", "text/plain; charset=utf-8"), ("Cache-Control", "no-store")];
                body = Text.encodeUtf8(pendingPrompt);
                upgrade = ?false;
            };
        };

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
        if (req.method == "GET" and req.url == "/api/response") {
            let resp = if (responseAvailable) latestResponse else "";
            latestResponse := "";
            responseAvailable := false;

            return {
                status_code = 200;
                headers = [
                    ("Content-Type", "text/plain; charset=utf-8"),
                    ("Cache-Control", "no-store, no-cache, must-revalidate"),
                    ("Access-Control-Allow-Origin", "*")
                ];
                body = Text.encodeUtf8(resp);
                upgrade = ?false;
            };
        };

        let decodedBody = Text.decodeUtf8(req.body);

        switch (decodedBody) {
            case (?textBody) {
                if (req.url == "/api/prompt") {
                    totalProcessed += 1;

                    switch (currentMode) {
                        case (#On) {
                            logThreat("Execution Lockout", "HIGH", previewText(textBody, 40));
                            return { status_code = 403; headers = []; body = Text.encodeUtf8("System Locked."); upgrade = ?false };
                        };
                        case (#Medium) {
                            switch (scanForThreats(textBody)) {
                                case (?threat) {
                                    logThreat(threat, "CRITICAL", previewText(textBody, 40));
                                    return { status_code = 406; headers = []; body = Text.encodeUtf8("Blocked by Medium Firewall."); upgrade = ?false };
                                };
                                case (null) { pendingPrompt := textBody; latestResponse := ""; };
                            };
                        };
                        case (#Off) { pendingPrompt := textBody; latestResponse := ""; };
                    };
                    return { status_code = 200; headers = []; body = Text.encodeUtf8("Queued"); upgrade = ?false };
                };

                if (req.url == "/api/result") {
                    latestResponse := textBody;
                    responseAvailable := true;
                    pendingPrompt := "";
                    return { status_code = 200; headers = []; body = Text.encodeUtf8("Result Saved"); upgrade = ?false };
                };
            };
            case (null) {
                return { status_code = 400; headers = []; body = Text.encodeUtf8("Invalid UTF-8"); upgrade = ?false };
            };
        };

        return { status_code = 404; headers = []; body = Text.encodeUtf8("Not Found"); upgrade = ?false };
    };
};
