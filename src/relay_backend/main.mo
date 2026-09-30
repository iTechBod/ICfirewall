import Time "mo:base/Time";
import Array "mo:base/Array";
import Text "mo:base/Text";
import Blob "mo:base/Blob";
import List "mo:base/List";
import Principal "mo:base/Principal";
import Nat "mo:base/Nat";
import RBTree "mo:base/RBTree";

actor RelayBackend {

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
        masterPid : Text;
        adminCount : Nat;
    };
    public type PromptResult = {
        allowed : Bool;
        mode : Text;
        response : Text;
        reason : Text;
        ticketId : ?Nat;
    };
    public type PendingTask = {
        ticketId : Nat;
        prompt : Text;
    };

    public type SecurityRulesConfig = {
        blockPromptInjection : Bool;
        blockDestructiveCommands : Bool;
        blockPrivilegeEscalation : Bool;
        maxContextLength : Nat;
    };

    public type HeaderField = (Text, Text);
    public type HttpRequest = { method : Text; url : Text; headers : [HeaderField]; body : Blob };
    public type HttpResponse = { status_code : Nat16; headers : [HeaderField]; body : Blob; upgrade : ?Bool };

    // --- Stable State ---
    stable var currentMode : FirewallMode = #Medium;
    stable var totalProcessed : Nat = 0;
    stable var totalBlocked : Nat = 0;
    
    stable var masterPrincipal : ?Principal = null; // Unassigned by default on clean GitHub repo deployment
    stable var adminPrincipals : [Principal] = [];
    
    stable var securityRules : SecurityRulesConfig = {
        blockPromptInjection = true;
        blockDestructiveCommands = true;
        blockPrivilegeEscalation = true;
        maxContextLength = 12000;
    };

    stable var nextTicketId : Nat = 1;
    stable var latestGlobalResponse : Text = "";
    stable var threatLog : [var ?ThreatEvent] = [var null, null, null, null, null, null, null, null, null, null];
    stable var logPointer : Nat = 0;

    private var promptQueue : List.List<(Nat, List.List<(Text, Text)>)> = List.nil();
    private var promptsMap = RBTree.RBTree<Nat, Text>(Nat.compare);
    private var resultsMap = RBTree.RBTree<Nat, Text>(Nat.compare);

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

    private func isMaster(p : Principal) : Bool {
        switch (masterPrincipal) {
            case (null) { false; };
            case (?m) { m == p; };
        }
    };

    private func isAdminOrMaster(p : Principal) : Bool {
        if (isMaster(p)) return true;
        for (admin in adminPrincipals.vals()) {
            if (admin == p) return true;
        };
        return false;
    };

    private func scanForThreats(payload : Text) : ?Text {
        let lower = Text.toLowercase(payload);

        if (securityRules.blockPromptInjection and (
            Text.contains(lower, #text "ignore previous instructions") or 
            Text.contains(lower, #text "system override") or 
            Text.contains(lower, #text "jailbreak") or 
            Text.contains(lower, #text "bypass rules") or
            Text.contains(lower, #text "disregard all prior"))) {
            return ?"Prompt Injection Blocked";
        };

        if (securityRules.blockDestructiveCommands and (
            Text.contains(lower, #text "rm -rf") or 
            Text.contains(lower, #text "format disk") or 
            Text.contains(lower, #text "mkfs") or
            Text.contains(lower, #text "drop table") or
            Text.contains(lower, #text "truncate table"))) {
            return ?"Destructive Manipulation Blocked";
        };

        if (securityRules.blockPrivilegeEscalation and (
            Text.contains(lower, #text "sudo ") or 
            Text.contains(lower, #text "chmod 777") or 
            Text.contains(lower, #text "/etc/passwd") or
            Text.contains(lower, #text "/etc/shadow") or
            Text.contains(lower, #text "chown root"))) {
            return ?"Privilege Escalation Blocked";
        };

        if (securityRules.maxContextLength > 0 and Text.size(payload) > securityRules.maxContextLength) {
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

    private func enqueuePrompt(item : Text) : Nat {
        let ticket = nextTicketId;
        nextTicketId += 1;
        promptsMap.put(ticket, item);
        promptQueue := List.append(promptQueue, ?((ticket, List.nil()), null));
        return ticket;
    };

    public query func getMasterPID() : async Text {
        switch (masterPrincipal) {
            case (null) { return "Unassigned"; };
            case (?p) { return Principal.toText(p); };
        };
    };

    public shared(msg) func getCallerPID() : async Text {
        return Principal.toText(msg.caller);
    };

    public shared(msg) func claimMasterPID(pidText : Text) : async Text {
        let caller = msg.caller;
        switch (masterPrincipal) {
            case (?m) {
                if (m != caller) {
                    return "Error: Master Principal already claimed.";
                };
            };
            case (null) {
                masterPrincipal := ?caller;
            };
        };
        return "Master ownership successfully claimed.";
    };

    public query func checkIsAdmin(pidText : Text) : async Bool {
        try {
            let p = Principal.fromText(pidText);
            return isAdminOrMaster(p);
        } catch (_) {
            return false;
        };
    };

    public query func getAdmins() : async [Text] {
        var res : [Text] = [];
        for (admin in adminPrincipals.vals()) {
            res := Array.append<Text>(res, [Principal.toText(admin)]);
        };
        return res;
    };

    public shared(msg) func addAdmin(pidText : Text) : async Text {
        if (not isMaster(msg.caller)) { return "Unauthorized: Master only."; };
        try {
            let p = Principal.fromText(pidText);
            if (isAdminOrMaster(p)) { return "Already an admin."; };
            adminPrincipals := Array.append<Principal>(adminPrincipals, [p]);
            return "Admin added successfully.";
        } catch (_) {
            return "Error: Invalid Principal format.";
        };
    };

    public shared(msg) func removeAdmin(pidText : Text) : async Text {
        if (not isMaster(msg.caller)) { return "Unauthorized: Master only."; };
        try {
            let target = Principal.fromText(pidText);
            var updated : [Principal] = [];
            for (admin in adminPrincipals.vals()) {
                if (admin != target) {
                    updated := Array.append<Principal>(updated, [admin]);
                };
            };
            adminPrincipals := updated;
            return "Admin revoked successfully.";
        } catch (_) {
            return "Error: Invalid Principal format.";
        };
    };

    public query func getSecurityRules() : async SecurityRulesConfig {
        return securityRules;
    };

    public shared(msg) func updateSecurityRules(newConfig : SecurityRulesConfig) : async Text {
        if (not isAdminOrMaster(msg.caller)) { return "Unauthorized: Admin/Master only."; };
        securityRules := newConfig;
        return "Security rules updated successfully.";
    };

    public query func getStats() : async SystemStats {
        let masterText = switch(masterPrincipal) { case(null) "Unassigned"; case(?p) Principal.toText(p); };
        return { 
            mode = getModeString(); 
            totalProcessed; 
            totalBlocked; 
            activeQueueLength = List.size(promptQueue);
            masterPid = masterText;
            adminCount = adminPrincipals.size();
        };
    };

    public shared(msg) func getPendingPrompt() : async ?PendingTask {
        switch (promptQueue) {
            case (null) { return null; };
            case (?((ticket, meta), tail)) {
                promptQueue := tail;
                switch (promptsMap.get(ticket)) {
                    case (null) { return null; };
                    case (?promptText) {
                        ignore promptsMap.remove(ticket);
                        return ?{ ticketId = ticket; prompt = promptText };
                    };
                };
            };
        };
    };

    public shared(msg) func saveResult(ticket : Nat, result : Text) : async Text {
        resultsMap.put(ticket, result);
        latestGlobalResponse := result;
        return "Result Saved";
    };

    public query func checkResponse(ticket : Nat) : async ?Text {
        switch (resultsMap.get(ticket)) {
            case (null) { return null; };
            case (?res) {
                return ?res;
            };
        };
    };

    public shared(msg) func setMode(newModeText : Text) : async Text {
        if (not isAdminOrMaster(msg.caller)) { return "Unauthorized: Admin/Master only."; };
        if (newModeText == "Off") { currentMode := #Off; }
        else if (newModeText == "On") { currentMode := #On; }
        else { currentMode := #Medium; };
        return "Mode updated.";
    };

    public shared(msg) func processPrompt(textBody : Text) : async PromptResult {
        totalProcessed += 1;
        let activeMode = getModeString();

        switch (currentMode) {
            case (#On) {
                logThreat("Execution Lockout", "HIGH", previewText(textBody, 40));
                return {
                    allowed = false;
                    mode = activeMode;
                    response = "BLOCKED: System Locked (ON boundary active).";
                    reason = "Execution Lockout active in ON posture.";
                    ticketId = null;
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
                            reason = threat;
                            ticketId = null;
                        };
                    };
                    case (null) { 
                        let tid = enqueuePrompt(textBody);
                        return {
                            allowed = true;
                            mode = activeMode;
                            response = "QUEUED: Prompt forwarded to Odysseus agent queue.";
                            reason = "Passed security heuristic filters.";
                            ticketId = ?tid;
                        };
                    };
                };
            };
            case (#Off) { 
                let tid = enqueuePrompt(textBody);
                return {
                    allowed = true;
                    mode = activeMode;
                    response = "QUEUED: Prompt forwarded to Odysseus agent queue.";
                    reason = "Firewall posture disabled.";
                    ticketId = ?tid;
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

    public query func http_request(req : HttpRequest) : async HttpResponse {
        let corsHeaders = [
            ("Access-Control-Allow-Origin", "*"),
            ("Access-Control-Allow-Methods", "POST, GET, OPTIONS"),
            ("Access-Control-Allow-Headers", "Content-Type"),
            ("Cache-Control", "no-store")
        ];
        if (req.method == "POST" or req.method == "OPTIONS") { return { status_code = 200; headers = corsHeaders; body = Blob.fromArray([]); upgrade = ?true }; };
        if (req.method == "GET" and (req.url == "/api/queue" or req.url == "/api/queue/")) { return { status_code = 200; headers = corsHeaders; body = Blob.fromArray([]); upgrade = ?true }; };
        if (req.method == "GET" and (req.url == "/api/response" or req.url == "/api/response/")) { return { status_code = 200; headers = corsHeaders; body = Blob.fromArray([]); upgrade = ?true }; };
        if (req.method == "GET" and Text.startsWith(req.url, #text "/api/check_response/")) { return { status_code = 200; headers = corsHeaders; body = Blob.fromArray([]); upgrade = ?true }; };
        return { status_code = 404; headers = corsHeaders; body = Text.encodeUtf8("Not Found"); upgrade = ?false };
    };

    public shared func http_request_update(req : HttpRequest) : async HttpResponse {
        let corsHeaders = [
            ("Access-Control-Allow-Origin", "*"), 
            ("Access-Control-Allow-Methods", "POST, GET, OPTIONS"), 
            ("Access-Control-Allow-Headers", "Content-Type"),
            ("Cache-Control", "no-store")
        ];
        if (req.method == "OPTIONS") { return { status_code = 204; headers = corsHeaders; body = Blob.fromArray([]); upgrade = ?false }; };
        
        if (req.method == "GET" and (req.url == "/api/queue" or req.url == "/api/queue/")) {
            var respText = "";
            switch (promptQueue) {
                case (null) {};
                case (?((ticket, meta), tail)) {
                    promptQueue := tail;
                    switch (promptsMap.get(ticket)) { 
                        case (?txt) { respText := txt; ignore promptsMap.remove(ticket); }; 
                        case (null) {}; 
                    };
                };
            };
            return { status_code = 200; headers = corsHeaders; body = Text.encodeUtf8(respText); upgrade = ?false };
        };

        if (req.method == "GET" and (req.url == "/api/response" or req.url == "/api/response/")) {
            let resp = latestGlobalResponse;
            return { status_code = 200; headers = corsHeaders; body = Text.encodeUtf8(resp); upgrade = ?false };
        };

        if (req.method == "GET" and Text.startsWith(req.url, #text "/api/check_response/")) {
            switch (Text.stripStart(req.url, #text "/api/check_response/")) {
                case (?ticketStr) {
                    switch (Nat.fromText(ticketStr)) {
                        case (?ticket) {
                            switch (resultsMap.get(ticket)) {
                                case (?res) {
                                    return { status_code = 200; headers = corsHeaders; body = Text.encodeUtf8(res); upgrade = ?false };
                                };
                                case (null) {
                                    return { status_code = 202; headers = corsHeaders; body = Text.encodeUtf8("PENDING"); upgrade = ?false };
                                };
                            };
                        };
                        case (null) {
                            return { status_code = 400; headers = corsHeaders; body = Text.encodeUtf8("Invalid Ticket ID"); upgrade = ?false };
                        };
                    };
                };
                case (null) {
                    return { status_code = 400; headers = corsHeaders; body = Text.encodeUtf8("Invalid Path"); upgrade = ?false };
                };
            };
        };

        let decodedBody = switch (Text.decodeUtf8(req.body)) { case (?t) t; case (null) ""; };
        if (req.url == "/api/prompt" or req.url == "/api/prompt/") {
            if (decodedBody == "") { return { status_code = 400; headers = corsHeaders; body = Text.encodeUtf8("Error: Empty Body"); upgrade = ?false }; };
            totalProcessed += 1;
            switch (currentMode) {
                case (#On) { return { status_code = 403; headers = corsHeaders; body = Text.encodeUtf8("BLOCKED: System Locked."); upgrade = ?false }; };
                case (#Medium) {
                    switch (scanForThreats(decodedBody)) {
                        case (?threat) { return { status_code = 406; headers = corsHeaders; body = Text.encodeUtf8("BLOCKED: " # threat); upgrade = ?false }; };
                        case (null) { 
                            let tid = enqueuePrompt(decodedBody);
                            return { status_code = 200; headers = corsHeaders; body = Text.encodeUtf8(Nat.toText(tid)); upgrade = ?false };
                        };
                    };
                };
                case (#Off) { 
                    let tid = enqueuePrompt(decodedBody);
                    return { status_code = 200; headers = corsHeaders; body = Text.encodeUtf8(Nat.toText(tid)); upgrade = ?false };
                };
            };
        };

        if (req.url == "/api/result" or req.url == "/api/result/") {
            latestGlobalResponse := decodedBody;
            return { status_code = 250; headers = corsHeaders; body = Text.encodeUtf8("Result Saved"); upgrade = ?false };
        };
        return { status_code = 404; headers = corsHeaders; body = Text.encodeUtf8("Not Found"); upgrade = ?false };
    };
};
