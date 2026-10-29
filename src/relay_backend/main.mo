import Time "mo:base/Time";
import Array "mo:base/Array";
import Text "mo:base/Text";
import Blob "mo:base/Blob";
import Principal "mo:base/Principal";
import Nat "mo:base/Nat";
import Char "mo:base/Char";
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

  // --- Constants & System Caps ---
  private let MAX_QUEUE_LIMIT : Nat = 200;
  private let HARD_MAX_PROMPT : Nat = 20000;

  // --- Stable State ---
  stable var currentMode : FirewallMode = #Medium;
  stable var totalProcessed : Nat = 0;
  stable var totalBlocked : Nat = 0;
  stable var nextTicketId : Nat = 1;
  stable var latestGlobalResponse : Text = "";

  stable var masterPrincipal : ?Principal = null;
  stable var daemonPrincipal : ?Principal = null;
  stable var adminPrincipals : [Principal] = [];
  stable var lastPromptTime : Int = 0;

  // Optional empty array for open-source public repository release (configure via setup wizard or dfx identities)
  private let KNOWN_MASTERS : [Text] = [];

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

  private func isKnownMasterText(pText : Text) : Bool {
    var found = false;
    for (m in KNOWN_MASTERS.vals()) {
      if (m == pText) {
        found := true;
      };
    };
    found
  };

  private func isMaster(p : Principal) : Bool {
    let pText = Principal.toText(p);
    if (isKnownMasterText(pText)) { return true };
    switch (masterPrincipal) {
      case (null) { false };
      case (?m) { m == p };
    }
  };

  private func isAdminOrMaster(p : Principal) : Bool {
    let pText = Principal.toText(p);
    if (isKnownMasterText(pText)) { return true };
    if (isMaster(p)) { return true };
    for (admin in adminPrincipals.vals()) {
      if (admin == p) { return true };
    };
    false
  };

  // ============================================================
  // TAMPERPROOF ON-CHAIN NORMALIZATION & THREAT ENGINE
  // ============================================================

  private func collapseWhitespace(t : Text) : Text {
    var result = "";
    var lastWasSpace = true;
    for (c in t.chars()) {
      let code = Char.toNat32(c);
      let isWs = 
        code == 0x20 or code == 0x09 or code == 0x0A or code == 0x0D or 
        code == 0x0B or code == 0x0C or code == 0xA0 or code == 0x85 or
        code == 0x1680 or code == 0x2028 or code == 0x2029 or
        (code >= 0x2000 and code <= 0x200A) or 
        code == 0x202F or code == 0x205F or code == 0x3000;

      if (isWs) {
        if (not lastWasSpace) {
          result #= " ";
          lastWasSpace := true;
        };
      } else {
        result #= Text.fromChar(c);
        lastWasSpace := false;
      };
    };
    result
  };

  private func stripZeroWidth(t : Text) : Text {
    var result = "";
    for (c in t.chars()) {
      let code = Char.toNat32(c);
      let isZeroWidth =
        code == 0x200B or  // zero-width space
        code == 0x200C or  // zero-width non-joiner
        code == 0x200D or  // zero-width joiner
        code == 0xFEFF or  // BOM / zero-width no-break space
        code == 0x00AD or  // soft hyphen
        code == 0x200E or  // LRM
        code == 0x200F or  // RLM
        code == 0x2060 or  // word joiner
        (code >= 0x202A and code <= 0x202E) or // bidi overrides
        (code >= 0x2066 and code <= 0x2069);    // directional isolates
      if (not isZeroWidth) {
        result #= Text.fromChar(c);
      };
    };
    result
  };

  private func normalizeForScan(t : Text) : Text {
    var folded = "";
    for (c in t.chars()) {
      let code = Char.toNat32(c);
      if (code >= 0xFF01 and code <= 0xFF5E) {
        folded #= Text.fromChar(Char.fromNat32(code - 0xFEE0));
      } else {
        folded #= Text.fromChar(c);
      };
    };

    var s = Text.toLowercase(folded);
    s := stripZeroWidth(s);
    s := Text.replace(s, #text "${ifs}", " ");
    s := Text.replace(s, #text "$ifs", " ");
    s := Text.replace(s, #text "\\t", " ");
    s := Text.replace(s, #text "\\n", " ");
    s := collapseWhitespace(s);
    s
  };

  private func shellView(t : Text) : Text {
    var r = "";
    for (c in t.chars()) {
      let k = Char.toNat32(c);
      let keep =
        (k >= 0x61 and k <= 0x7A) or (k >= 0x30 and k <= 0x39) or
        k == 0x20 or k == 0x2D or k == 0x2F or k == 0x2E or k == 0x3D or k == 0x5F or k > 0x7F;
      if (keep) { r #= Text.fromChar(c) } else { r #= " " };
    };
    " " # collapseWhitespace(r) # " "
  };

  private func hit(a : Text, b : Text, p : Text) : Bool {
    Text.contains(a, #text p) or Text.contains(b, #text p)
  };

  private func containsWord(haystack : Text, word : Text) : Bool {
    if (haystack == word) { return true };
    if (Text.startsWith(haystack, #text (word # " "))) { return true };
    if (Text.endsWith(haystack, #text (" " # word))) { return true };
    if (Text.contains(haystack, #text (" " # word # " "))) { return true };
    false
  };

  private func deleet(t : Text) : Text {
    var result = "";
    for (c in t.chars()) {
      let code = Char.toNat32(c);
      let normalized : Char =
        if (code == 0x30) { 'o' }
        else if (code == 0x31) { 'i' }
        else if (code == 0x33) { 'e' }
        else if (code == 0x34) { 'a' }
        else if (code == 0x35) { 's' }
        else if (code == 0x37) { 't' }
        else if (code == 0x40) { 'a' }
        else { c };
      result #= Text.fromChar(normalized);
    };
    result
  };

  private let DESTRUCTIVE_PATTERNS : [Text] = [
    "rm -rf", "rm -fr", "rm -r -f", "rm -f -r",
    "rm --recursive", "rm --force", "rm -rf /", "rm -rf ~",
    "del /s", "del /q", "deltree", "rmdir /s",
    "format c:", "mkfs.", " dd if=", " dd of=",
    ">/dev/sda", ">/dev/nvme", "drop database", "drop table",
    "truncate table", "shutdown -h", "shutdown now",
    "shutdown /s", "reboot now", "init 0", "poweroff now",
    ":(){:|:&};:"
  ];

  private let ON_DESTRUCTIVE_PATTERNS : [Text] = [
    "delete from "
  ];

  private let INJECTION_PATTERNS : [Text] = [
    "system override", "disregard all prior", "disregard all previous",
    "ignore previous instructions", "ignore all previous", "jailbreak",
    "dan mode", "do anything now", "bypass rules", "bypass safety",
    "new instructions:"
  ];

  private let STRICT_INJECTION_PATTERNS : [Text] = [
    "you are now", "pretend to be", "act as if", "roleplay as"
  ];

  private let PRIVILEGE_PATTERNS : [Text] = [
    "sudo sh", "sudo bash", "sudo su", "sudo -i", "su root",
    "chmod 777", "chown root", "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "visudo", "reverse shell", " nc -e"
  ];

  private func scanForThreatsMedium(payload : Text) : ?(Text, Text) {
    let normalized = normalizeForScan(payload);
    let view = shellView(normalized);

    if (securityRulesConfig.maxContextLength > 0 and Text.size(payload) > securityRulesConfig.maxContextLength) {
      return ?("Context Overflow Blocked", "MEDIUM");
    };

    if (securityRulesConfig.blockPromptInjection) {
      for (p in INJECTION_PATTERNS.vals()) {
        if (hit(normalized, view, p)) {
          return ?("Prompt Injection Blocked", "HIGH");
        };
      };
    };

    if (securityRulesConfig.blockDestructiveCommands) {
      for (p in DESTRUCTIVE_PATTERNS.vals()) {
        if (hit(normalized, view, p)) {
          return ?("Destructive Command Blocked", "CRITICAL");
        };
      };
    };

    if (securityRulesConfig.blockPrivilegeEscalation) {
      for (p in PRIVILEGE_PATTERNS.vals()) {
        if (hit(normalized, view, p)) {
          return ?("Privilege Escalation Blocked", "CRITICAL");
        };
      };
      if (containsWord(view, "sudo")) {
        return ?("Privilege Escalation Blocked", "CRITICAL");
      };
    };

    null
  };

  private func scanForThreatsOn(payload : Text) : ?(Text, Text) {
    var maxLen = securityRulesConfig.maxContextLength;
    if (maxLen == 0 or maxLen > HARD_MAX_PROMPT) { maxLen := HARD_MAX_PROMPT };
    if (maxLen > 4000) { maxLen := 4000 };

    if (Text.size(payload) > maxLen) {
      return ?("Context Overflow (Strict limit)", "HIGH");
    };

    switch (scanForThreatsMedium(payload)) {
      case (?threat) { return ?threat };
      case (null) {};
    };

    let normalized = normalizeForScan(payload);
    let view = shellView(normalized);

    if (securityRulesConfig.blockPromptInjection) {
      for (p in STRICT_INJECTION_PATTERNS.vals()) {
        if (hit(normalized, view, p)) {
          return ?("Prompt Injection (Strict)", "HIGH");
        };
      };
    };

    for (p in ON_DESTRUCTIVE_PATTERNS.vals()) {
      if (hit(normalized, view, p)) {
        return ?("Destructive Command Blocked", "CRITICAL");
      };
    };

    let deleeted = deleet(normalized);
    let deleetedView = shellView(deleeted);

    if (deleeted != normalized) {
      for (p in INJECTION_PATTERNS.vals()) {
        if (hit(deleeted, deleetedView, p)) {
          return ?("Prompt Injection (Obfuscated)", "CRITICAL");
        };
      };
      for (p in DESTRUCTIVE_PATTERNS.vals()) {
        if (hit(deleeted, deleetedView, p)) {
          return ?("Destructive Command (Obfuscated)", "CRITICAL");
        };
      };
      for (p in ON_DESTRUCTIVE_PATTERNS.vals()) {
        if (hit(deleeted, deleetedView, p)) {
          return ?("Destructive Command (Obfuscated)", "CRITICAL");
        };
      };
      for (p in PRIVILEGE_PATTERNS.vals()) {
        if (hit(deleeted, deleetedView, p)) {
          return ?("Privilege Escalation (Obfuscated)", "CRITICAL");
        };
      };
      if (containsWord(deleetedView, "sudo")) {
        return ?("Privilege Escalation (Obfuscated)", "CRITICAL");
      };
      for (p in STRICT_INJECTION_PATTERNS.vals()) {
        if (hit(deleeted, deleetedView, p)) {
          return ?("Prompt Injection (Obfuscated Strict)", "HIGH");
        };
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
      case (null) {
        if (KNOWN_MASTERS.size() > 0) {
          KNOWN_MASTERS[0]
        } else {
          "Unassigned"
        }
      };
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
    if (Principal.isAnonymous(caller)) {
      return "Error: Anonymous principal cannot claim master ownership.";
    };
    masterPrincipal := ?caller;
    "Master ownership successfully claimed.";
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

  public shared query(msg) func getAdmins() : async [Text] {
    if (not isAdminOrMaster(msg.caller)) {
      return [];
    };
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
      case (null) { 
        if (KNOWN_MASTERS.size() > 0) { KNOWN_MASTERS[0] } else { "Unassigned" }
      };
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
      case (null) {
        if (not isAdminOrMaster(msg.caller)) {
          return null;
        }
      };
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
      case (null) {
        if (not isAdminOrMaster(msg.caller)) {
          return "Unauthorized: Daemon/Admin only.";
        }
      };
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

    var maxLen = securityRulesConfig.maxContextLength;
    if (maxLen == 0 or maxLen > HARD_MAX_PROMPT) { maxLen := HARD_MAX_PROMPT };
    if (currentMode == #On and maxLen > 4000) { maxLen := 4000 };

    if (Text.size(textBody) > maxLen) {
      return {
        allowed = false;
        mode = activeMode;
        response = "BLOCKED: Prompt exceeds maximum permitted context length.";
        reason = "Context Overflow";
        ticketId = null;
      };
    };

    if (now - lastPromptTime < 100_000_000) {
      return {
        allowed = false;
        mode = activeMode;
        response = "BLOCKED: Rate limited.";
        reason = "Rate limit exceeded.";
        ticketId = null;
      };
    };

    if (promptQueueBuffer.size() >= MAX_QUEUE_LIMIT) {
      return {
        allowed = false;
        mode = activeMode;
        response = "BLOCKED: System queue at maximum capacity.";
        reason = "Capacity cap reached.";
        ticketId = null;
      };
    };

    lastPromptTime := now;
    totalProcessed += 1;

    switch (currentMode) {
      case (#On) {
        switch (scanForThreatsOn(textBody)) {
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
              reason = "Passed strict heuristic filters.";
              ticketId = ?tid;
            }
          };
        }
      };
      case (#Medium) {
        switch (scanForThreatsMedium(textBody)) {
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

  public shared query(msg) func getThreats() : async [ThreatEvent] {
    if (not isAdminOrMaster(msg.caller)) {
      return [];
    };
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
