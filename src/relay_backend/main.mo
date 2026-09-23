import Text "mo:base/Text";
import Array "mo:base/Array";
import Time "mo:base/Time";
import List "mo:base/List";
import Principal "mo:base/Principal";

actor ICfirewall {

  public type SystemStats = {
    mode : Text;
    activeQueueLength : Nat;
    totalProcessed : Nat;
    totalBlocked : Nat;
  };

  public type ThreatEvent = {
    timestamp : Int;
    threatType : Text;
    severity : Text;
    snippet : Text;
  };

  public type PromptResult = {
    allowed : Bool;
    mode : Text;
    response : Text;
    reason : Text;
  };

  private var currentMode : Text = "Medium";
  private var processedCount : Nat = 0;
  private var blockedCount : Nat = 0;
  private var queueCount : Nat = 0;

  private var threatLog : List.List<ThreatEvent> = List.nil<ThreatEvent>();

  public query func getStats() : async SystemStats {
    return {
      mode = currentMode;
      activeQueueLength = queueCount;
      totalProcessed = processedCount;
      totalBlocked = blockedCount;
    };
  };

  public query func getThreats() : async [ThreatEvent] {
    return List.toArray(threatLog);
  };

  public func setMode(newMode : Text) : async Text {
    currentMode := newMode;
    return "Mode updated.";
  };

  public func processPrompt(prompt : Text) : async PromptResult {
    processedCount += 1;
    let lower = Text.toLower(prompt);
    let now = Time.now();

    if (currentMode == "On") {
      if (containsKeyword(lower, "ignore") or containsKeyword(lower, "system") or containsKeyword(lower, "key") or containsKeyword(lower, "eval")) {
        blockedCount += 1;
        recordThreat(now, "Strict Boundary Breach", "High", prompt);
        return {
          allowed = false;
          mode = currentMode;
          response = "[BLOCKED] Prompt violates strict boundary safety constraints.";
          reason = "System rules prohibited keyword execution under ON posture.";
        };
      };
    } else if (currentMode == "Medium") {
      if (containsKeyword(lower, "malware") or containsKeyword(lower, "exploit") or containsKeyword(lower, "bypass")) {
        blockedCount += 1;
        recordThreat(now, "Exploit Attempt", "Medium", prompt);
        return {
          allowed = false;
          mode = currentMode;
          response = "[BLOCKED] High-risk payload detected by guardrails.";
          reason = "Contains prohibited vulnerability or exploit pattern.";
        };
      };
    };

    return {
      allowed = true;
      mode = currentMode;
      response = "Prompt cleared security boundary [" # currentMode # "]. Relayed to local model target.";
      reason = "No violation detected.";
    };
  };

  private func recordThreat(timestamp : Int, threatType : Text, severity : Text, snippet : Text) {
    let truncatedSnippet = if (Text.len(snippet) > 40) {
      Text.substring(snippet, 0, 40) # "..."
    } else {
      snippet
    };

    let event : ThreatEvent = {
      timestamp = timestamp;
      threatType = threatType;
      severity = severity;
      snippet = truncatedSnippet;
    };

    threatLog := List.push(event, threatLog);
  };

  private func containsKeyword(text : Text, keyword : Text) : Bool {
    switch (Text.findSubstring(text, keyword)) {
      case (?_) true;
      case null false;
    };
  };
};
