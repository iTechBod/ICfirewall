import Time "mo:base/Time";
import Array "mo:base/Array";
import Text "mo:base/Text";
import Blob "mo:base/Blob";
import List "mo:base/List";

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
    public type PromptResult = {
        allowed : Bool;
        mode : Text;
        response : Text;
        reason : Text;
    };

    public type HeaderField = (Text, Text);
    public type HttpRequest = { method : Text; url : Text; headers : [HeaderField]; body : Blob };
    public type HttpResponse = { status_code : Nat16; headers : [HeaderField]; body : Blob; upgrade : ?Bool };

    // --- State Variables ---
    private var currentMode : FirewallMode = #Medium;
    private var totalProcessed : Nat = 0;
    private var totalBlocked : Nat = 0;
    
    // FIFO Queue for multi-prompt processing
    private var promptQueue : List.List<Text> = List.nil();
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

    private func getModeString() : Text {
        switch(currentMode) { 
            case(#Off) "OFF"; 
            case(#Medium) "MEDIUM"; 
            case(#On) "ON"; 
        }
    };

    private func enqueuePrompt(item : Text) {
        promptQueue := List.append(promptQueue, ?(item, List.nil()));
    };

    private func dequeuePrompt() : Text {
        switch (promptQueue) {
            case (null) "";
            case (?(head, tail)) {
                promptQueue := tail;
                head;
            };
        };
    };

    public query func getStats() : async SystemStats {
        return { 
            mode = getModeString(); 
            totalProcessed; 
            totalBlocked; 
            activeQueueLength = List.size(promptQueue); 
        };
    };

    public shared func getPendingPrompt() : async Text {
        dequeuePrompt()
    };

    public shared func saveResult(result : Text) : async Text {
        latestResponse := result;
        responseAvailable := true;
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
    public shared func processPrompt(textBody : Text) : async PromptResult {
        totalProcessed += 1;
        let activeMode = getModeString();

        switch (currentMode) {
            case (#On) {
                logThreat("Execution Lockout", "HIGH", previewText(textBody, 40));
                return {
                    allowed = false;
                    mode = activeMode;
                    response = "BLOCKED: System Locked (ON boundary active).";
                    reason = "Execution Lockout active in ON posture."
                };
            };
            case (#Medium) {
                switch (scanForThreats(textBody)) {
                    case (?threat) {
                        logThreat(threat, "CRITICAL", previewText(textBody, 40));
                        return {
                            allowed = false;
                            mode = activeMode;
                            response = "BLOCKED: " # threat;
                            reason = threat
                        };
                    };
                    case (null) { 
                        enqueuePrompt(textBody);
                        latestResponse := ""; 
                        return {
                            allowed = true;
                            mode = activeMode;
                            response = "QUEUED: Prompt forwarded to Odysseus agent queue.";
                            reason = "Passed security heuristic filters."
                        };
                    };
                };
            };
            case (#Off) { 
                enqueuePrompt(textBody);
                latestResponse := ""; 
                return {
                    allowed = true;
                    mode = activeMode;
                    response = "QUEUED: Prompt forwarded to Odysseus agent queue.";
                    reason = "Firewall posture disabled."
                };
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

    // --- HTTP Gateway for iOS Shortcuts and Raw HTTP Clients ---
    public query func http_request(req : HttpRequest) : async HttpResponse {
        if (req.method == "POST" or req.method == "OPTIONS") {
            return { status_code = 200; headers = []; body = Blob.fromArray([]); upgrade = ?true };
        };
        
        if (req.method == "GET" and (req.url == "/api/queue" or req.url == "/api/queue/")) {
            return {
                status_code = 200;
                headers = [];
                body = Blob.fromArray([]);
                upgrade = ?true;
            };
        };

        if (req.method == "GET" and (req.url == "/api/response" or req.url == "/api/response/")) {
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
        let corsHeaders = [
            ("Access-Control-Allow-Origin", "*"),
            ("Access-Control-Allow-Methods", "POST, GET, OPTIONS"),
            ("Access-Control-Allow-Headers", "Content-Type"),
            ("Cache-Control", "no-store, no-cache, must-revalidate")
        ];

        if (req.method == "OPTIONS") {
            return { status_code = 204; headers = corsHeaders; body = Blob.fromArray([]); upgrade = ?false };
        };

        if (req.method == "GET" and (req.url == "/api/queue" or req.url == "/api/queue/")) {
            let nextItem = dequeuePrompt();
            return {
                status_code = 200;
                headers = corsHeaders;
                body = Text.encodeUtf8(nextItem);
                upgrade = ?false;
            };
        };

        if (req.method == "GET" and (req.url == "/api/response" or req.url == "/api/response/")) {
            let resp = if (responseAvailable) latestResponse else "";
            latestResponse := "";
            responseAvailable := false;

            return {
                status_code = 200;
                headers = corsHeaders;
                body = Text.encodeUtf8(resp);
                upgrade = ?false;
            };
        };

        let decodedBody = switch (Text.decodeUtf8(req.body)) {
            case (?t) t;
            case (null) "";
        };

        if (req.url == "/api/prompt" or req.url == "/api/prompt/") {
            if (decodedBody == "") {
                return { status_code = 400; headers = corsHeaders; body = Text.encodeUtf8("Error: Empty Body"); upgrade = ?false };
            };

            totalProcessed += 1;

            switch (currentMode) {
                case (#On) {
                    logThreat("Execution Lockout", "HIGH", previewText(decodedBody, 40));
                    return { status_code = 403; headers = corsHeaders; body = Text.encodeUtf8("BLOCKED: System Locked."); upgrade = ?false };
                };
                case (#Medium) {
                    switch (scanForThreats(decodedBody)) {
                        case (?threat) {
                            logThreat(threat, "CRITICAL", previewText(decodedBody, 40));
                            return { status_code = 406; headers = corsHeaders; body = Text.encodeUtf8("BLOCKED: " # threat); upgrade = ?false };
                        };
                        case (null) { 
                            enqueuePrompt(decodedBody); 
                            latestResponse := ""; 
                        };
                    };
                };
                case (#Off) { 
                    enqueuePrompt(decodedBody); 
                    latestResponse := ""; 
                };
            };

            return { status_code = 200; headers = corsHeaders; body = Text.encodeUtf8("QUEUED"); upgrade = ?false };
        };

        if (req.url == "/api/result" or req.url == "/api/result/") {
            latestResponse := decodedBody;
            responseAvailable := true;
            return { status_code = 200; headers = corsHeaders; body = Text.encodeUtf8("Result Saved"); upgrade = ?false };
        };

        return { status_code = 404; headers = corsHeaders; body = Text.encodeUtf8("Not Found"); upgrade = ?false };
    };
};
