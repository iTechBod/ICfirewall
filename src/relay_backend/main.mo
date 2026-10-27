import Time "mo:base/Time";
import Array "mo:base/Array";
import Text "mo:base/Text";
import Blob "mo:base/Blob";
import Principal "mo:base/Principal";
import Nat "mo:base/Nat";
import RBTree "mo:base/RBTree";
import Buffer "mo:base/Buffer";

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
    daemonPid : Text;
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
  public type HttpRequest = {
    method : Text;
    url : Text;
    headers : [HeaderField];
    body : Blob;
  };
  public type HttpResponse = {
    status_code : Nat16;
    headers : [HeaderField];
    body : Blob;
    upgrade : ?Bool;
  };

  // --- Stable State ---
  stable var currentMode : FirewallMode = #Medium;
  stable var totalProcessed : Nat = 0;
  stable var totalBlocked : Nat = 0;
  stable var nextTicketId : Nat = 1;
  stable var latestGlobalResponse : Text = "";

  // To set your master before deploying, uncomment the line below and replace the placeholder.
  // stable var masterPrincipal : ?Principal = ?Principal.fromText("YOUR_MASTER_PRINCIPAL_ID_HERE");
  // Leaving it null means the first caller of claimMasterPID becomes master — NOT recommended for production.
  stable var masterPrincipal : ?Principal = null;
  stable var daemonPrincipal : ?Principal = null;
  stable var adminPrincipals : [Principal] = [];
  stable var lastPromptTime : Int = 0;

  stable var securityRulesConfig : SecurityRulesConfig = {
    blockPromptInjection = true;
    blockDestructiveCommands = true;
    blockPrivilegeEscalation = true;
    maxContextLength = 12000;
  };

  stable var threatLog : [var ?ThreatEvent] = [var null, null, null, null, null, null, null, null, null, null];
  stable var logPointer : Nat = 0;

  private var promptQueueBuffer = Buffer.Buffer<Nat>(10);
  private var promptsMap = RBTree.RBTree<Nat, Text>(Nat.compare);
  private var resultsMap = RBTree.RBTree<Nat, Text>(Nat.compare);
  private var resultTimestamps = RBTree.RBTree<Nat, Int>(Nat.compare);

  private func previewText(t : Text, maxLen : Nat) : Text {
    if (t.size() <= maxLen) { return t };
    var result = "";
    var count : Nat = 0;
    for (c in t.chars()) {
      if (count >= maxLen) { return result };
      result #= Text.fromChar(c);
      count += 1;
    };
    result
  };

  private func logThreat(threatType : Text, severity : Text, snippet : Text) {
    threatLog[logPointer] := ?{
      timestamp = Time.now();
      threatType;
      severity;
      snippet;
    };
    logPointer := (logPointer + 1) % 10;
    totalBlocked += 1;
  };

  private func isMaster(p : Principal) : Bool {
    switch (masterPrincipal) {
      case (null) { false };
      case (?m) { m == p };
    }
  };

  private func isAdminOrMaster(p : Principal) : Bool {
    if (isMaster(p)) { return true };
    for (admin in adminPrincipals.vals()) {
      if (admin == p) { return true };
    };
    false
  };

  private func scanForThreats(payload : Text) : ?(Text, Text) {
    let lower = Text.toLowercase(payload);
    if (securityRulesConfig.maxContextLength > 0 and Text.size(payload) > securityRulesConfig.maxContextLength) {
      return ?("Context Overflow Blocked", "MEDIUM");
    };
    if (securityRulesConfig.blockPromptInjection) {
      if (Text.contains(lower, #text "system override") or
          Text.contains(lower, #text "disregard all prior")) {
        return ?("Prompt Injection Blocked", "CRITICAL");
      } else if (Text.contains(lower, #text "ignore previous instructions") or
                 Text.contains(lower, #text "jailbreak") or
                 Text.contains(lower, #text "bypass rules")) {
        return ?("Prompt Injection Blocked", "HIGH");
      };
    };
    if (securityRulesConfig.blockDestructiveCommands) {
      if (Text.contains(lower, #text "rm -rf") or
          Text.contains(lower, #text "drop table") or
          Text.contains(lower, #text "format disk") or
          Text.contains(lower, #text "mkfs") or
          Text.contains(lower, #text "truncate table")) {
        return ?("Destructive Command Blocked", "CRITICAL");
      };
    };
    if (securityRulesConfig.blockPrivilegeEscalation) {
      if (Text.contains(lower, #text "sudo ") or
          Text.contains(lower, #text "/etc/passwd") or
          Text.contains(lower, #text "/etc/shadow") or
          Text.contains(lower, #text "chmod 777") or
          Text.contains(lower, #text "chown root")) {
        return ?("Privilege Escalation Blocked", "CRITICAL");
      };
    };
    null
  };

  private func getModeString() : Text {
    switch (currentMode) {
      case (#Off) { "OFF" };
      case (#Medium) { "MEDIUM" };
      case (#On) { "ON" };
    }
  };

  private func enqueuePrompt(item : Text) : Nat {
    let ticket = nextTicketId;
    nextTicketId += 1;
    promptsMap.put(ticket, item);
    promptQueueBuffer.add(ticket);
    ticket
  };

  public query func getMasterPID() : async Text {
    switch (masterPrincipal) {
      case (null) { "Unassigned" };
      case (?p) { Principal.toText(p) };
    }
  };

  public query func getDaemonPID() : async Text {
    switch (daemonPrincipal) {
      case (null) { "Unassigned" };
      case (?p) { Principal.toText(p) };
    }
  };

  public shared(msg) func claimMasterPID(pidText : Text) : async Text {
    let caller = msg.caller;
    switch (masterPrincipal) {
      case (?m) {
        if (m != caller) { return "Error: Master Principal already claimed."; };
        "Master ownership already held by caller."
      };
      case (null) {
        masterPrincipal := ?caller;
        "Master ownership successfully claimed.";
      };
    }
  };

  public shared(msg) func setDaemonPrincipal(pidText : Text) : async Text {
    if (not isAdminOrMaster(msg.caller)) {
      return "Unauthorized: Admin/Master only.";
    };
    try {
      daemonPrincipal := ?Principal.fromText(pidText);
      return "Daemon principal authorized.";
    } catch (_) {
      return "Error: Invalid Principal format.";
    };
  };

  public query func checkIsAdmin(pidText : Text) : async Bool {
    try {
      let p = Principal.fromText(pidText);
      isAdminOrMaster(p)
    } catch (_) {
      false
    }
  };

  public query func getAdmins() : async [Text] {
    let buf = Buffer.Buffer<Text>(adminPrincipals.size());
    for (admin in adminPrincipals.vals()) {
      buf.add(Principal.toText(admin));
    };
    Buffer.toArray(buf)
  };

  public shared(msg) func addAdmin(pidText : Text) : async Text {
    if (not isMaster(msg.caller)) {
      return "Unauthorized: Master only.";
    };
    try {
      let p = Principal.fromText(pidText);
      if (isAdminOrMaster(p)) {
        return "Already an admin.";
      };
      adminPrincipals := Array.append(adminPrincipals, [p]);
      "Admin added successfully."
    } catch (_) {
      "Error: Invalid Principal format."
    }
  };

  public shared(msg) func removeAdmin(pidText : Text) : async Text {
    if (not isMaster(msg.caller)) {
      return "Unauthorized: Master only.";
    };
    try {
      let target = Principal.fromText(pidText);
      let buf = Buffer.Buffer<Principal>(adminPrincipals.size());
      for (admin in adminPrincipals.vals()) {
        if (admin != target) {
          buf.add(admin);
        };
      };
      adminPrincipals := Buffer.toArray(buf);
      "Admin revoked successfully."
    } catch (_) {
      "Error: Invalid Principal format."
    }
  };

  public query func getSecurityRules() : async SecurityRulesConfig {
    securityRulesConfig
  };

  public shared(msg) func updateSecurityRules(newConfig : SecurityRulesConfig) : async Text {
    if (not isAdminOrMaster(msg.caller)) {
      return "Unauthorized: Admin/Master only.";
    };
    securityRulesConfig := newConfig;
    "Security rules updated successfully."
  };

  public query func getStats() : async SystemStats {
    let masterText = switch (masterPrincipal) {
      case (null) { "Unassigned" };
      case (?p) { Principal.toText(p) };
    };
    let daemonText = switch (daemonPrincipal) {
      case (null) { "Unassigned" };
      case (?p) { Principal.toText(p) };
    };

    {
      mode = getModeString();
      totalProcessed;
      totalBlocked;
      activeQueueLength = promptQueueBuffer.size();
      masterPid = masterText;
      daemonPid = daemonText;
      adminCount = adminPrincipals.size();
    }
  };

  public shared(msg) func getPendingPrompt() : async ?PendingTask {
    switch (daemonPrincipal) {
      case (?d) {
        if (msg.caller != d and not isAdminOrMaster(msg.caller)) {
          return null;
        };
      };
      case (null) {};
    };
    
    if (promptQueueBuffer.size() == 0) {
      return null;
    };

    let ticket = promptQueueBuffer.get(0);
    ignore promptQueueBuffer.remove(0);

    switch (promptsMap.get(ticket)) {
      case (null) { return null; };
      case (?promptText) {
        ignore promptsMap.remove(ticket);
        return ?{ ticketId = ticket; prompt = promptText };
      };
    };
  };

  public shared(msg) func saveResult(ticket : Nat, result : Text) : async Text {
    switch (daemonPrincipal) {
      case (?d) {
        if (msg.caller != d and not isAdminOrMaster(msg.caller)) {
          return "Unauthorized: Daemon/Admin only.";
        };
      };
      case (null) {};
    };
    resultsMap.put(ticket, result);
    resultTimestamps.put(ticket, Time.now());
    latestGlobalResponse := result;
    return "Result Saved";
  };

  public query func checkResponse(ticket : Nat) : async ?Text {
    resultsMap.get(ticket)
  };

  public shared(msg) func setMode(newModeText : Text) : async Text {
    if (not isAdminOrMaster(msg.caller)) {
      return "Unauthorized: Admin/Master only.";
    };
    if (newModeText == "Off") {
      currentMode := #Off;
    } else if (newModeText == "On") {
      currentMode := #On;
    } else {
      currentMode := #Medium;
    };
    "Mode updated."
  };

  public shared(msg) func processPrompt(textBody : Text) : async PromptResult {
    let activeMode = getModeString();
    let now = Time.now();
    if (now - lastPromptTime < 100_000_000) {
      return {
        allowed = false;
        mode = activeMode;
        response = "BLOCKED: Rate limited.";
        reason = "Rate limit exceeded.";
        ticketId = null;
      };
    };
    lastPromptTime := now;
    totalProcessed += 1;

    switch (currentMode) {
      case (#On) {
        logThreat("Execution Lockout", "HIGH", previewText(textBody, 40));
        {
          allowed = false;
          mode = activeMode;
          response = "BLOCKED: System Locked (ON boundary active).";
          reason = "Execution Lockout active in ON posture.";
          ticketId = null;
        }
      };
      case (#Medium) {
        switch (scanForThreats(textBody)) {
          case (?(threat, severity)) {
            logThreat(threat, severity, previewText(textBody, 40));
            {
              allowed = false;
              mode = activeMode;
              response = "BLOCKED: " # threat;
              reason = threat;
              ticketId = null;
            }
          };
          case (null) {
            let tid = enqueuePrompt(textBody);
            {
              allowed = true;
              mode = activeMode;
              response = "QUEUED: Prompt forwarded to authenticated daemon queue.";
              reason = "Passed security heuristic filters.";
              ticketId = ?tid;
            }
          };
        }
      };
      case (#Off) {
        let tid = enqueuePrompt(textBody);
        {
          allowed = true;
          mode = activeMode;
          response = "QUEUED: Prompt forwarded to authenticated daemon queue.";
          reason = "Firewall posture disabled.";
          ticketId = ?tid;
        }
      };
    }
  };

  public query func getThreats() : async [ThreatEvent] {
    let buf = Buffer.Buffer<ThreatEvent>(threatLog.size());
    for (item in threatLog.vals()) {
      switch (item) {
        case (?event) { buf.add(event); };
        case (null) {};
      };
    };
    Buffer.toArray(buf)
  };

  public query func http_request(req : HttpRequest) : async HttpResponse {
    { status_code = 404; headers = [("Access-Control-Allow-Origin", "*")]; body = Text.encodeUtf8("Not Found"); upgrade = ?false }
  };

  public shared func http_request_update(req : HttpRequest) : async HttpResponse {
    { status_code = 404; headers = [("Access-Control-Allow-Origin", "*")]; body = Text.encodeUtf8("Not Found"); upgrade = ?false }
  };
};
