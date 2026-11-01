import Time "mo:base/Time";
import Array "mo:base/Array";
import Text "mo:base/Text";
import Blob "mo:base/Blob";
import Principal "mo:base/Principal";
import Nat "mo:base/Nat";
import Nat8 "mo:base/Nat8";
import Nat32 "mo:base/Nat32";
import Char "mo:base/Char";
import Iter "mo:base/Iter";
import RBTree "mo:base/RBTree";
import Buffer "mo:base/Buffer";
import Timer "mo:base/Timer";
import Debug "mo:base/Debug";
import Cycles "mo:base/ExperimentalCycles";

shared ({ caller = installer }) actor class RelayBackend() {

  // ---------------------------------------------------------------- types
  public type FirewallMode = { #Off; #Medium; #On };
  public type InitializationState = { #Uninitialized; #Initializing; #Initialized };
  public type ThreatEvent = { timestamp : Int; threatType : Text; severity : Text; snippet : Text };
  public type SystemStats = {
    mode : Text; totalProcessed : Nat; totalBlocked : Nat; activeQueueLength : Nat;
    adminCount : Nat; masterPid : Text; daemonPid : Text;
  };
  public type PromptResult = { allowed : Bool; mode : Text; response : Text; reason : Text; ticketId : ?Nat };

  public type TicketState = {
    #Reserved; #Submitted; #Processing : (Int, Nat); #Completed; #DeadLetter; #Expired;
  };
  public type TaskType = { #Inspected : Text; #Private : Blob };
  public type PendingTask = { ticketId : Nat; taskType : TaskType; leaseToken : Nat; attemptCount : Nat };
  public type TicketReservationRecord = {
    owner : Principal; queueSlotReserved : Bool; resultCapacityReserved : Bool; bytesReserved : Nat;
    principalQuotaReserved : Bool; activeCounted : Bool; released : Bool;
  };
  public type SecurityRulesConfig = {
    blockPromptInjection : Bool; blockDestructiveCommands : Bool;
    blockPrivilegeEscalation : Bool; maxContextLength : Nat;
  };

  type VetKdKeyId = { curve : { #bls12_381_g2 }; name : Text };
  type MgmtActor = actor {
    vetkd_public_key : ({ canister_id : ?Principal; context : Blob; key_id : VetKdKeyId }) -> async { public_key : Blob };
    vetkd_derive_key : ({ input : Blob; context : Blob; transport_public_key : Blob; key_id : VetKdKeyId }) -> async { encrypted_key : Blob };
  };
  private let mgmt : MgmtActor = actor ("aaaaa-aa");

  // ---------------------------------------------------------------- constants
  private let MAX_QUEUE_LIMIT : Nat = 200;
  private let MAX_ACTIVE_TICKETS : Nat = 150;
  private let MAX_GLOBAL_RESERVATIONS : Nat = 100;
  private let MAX_PRINCIPAL_RESERVATIONS : Nat = 5;
  private let MAX_PRINCIPAL_ACTIVE : Nat = 10;
  private let MAX_RETAINED_RESULTS : Nat = 1000;
  private let MAX_RETAINED_BYTES : Nat = 10 * 1024 * 1024;
  private let EXPECTED_MAX_RESPONSE_BYTES : Nat = 64000;
  private let MAX_RETRY_COUNT : Nat = 3;
  private let HARD_MAX_PROMPT : Nat = 20000;
  private let MAX_CIPHERTEXT_BYTES : Nat = 64000;
  private let MAX_THREAT_LOG : Nat = 50;
  private let MAX_ADMINS : Nat = 10;
  private let MAX_DERIVES_PER_TICKET : Nat = 4;
  private let RATE_GAP_NS : Int = 500_000_000;
  private let RESULT_TTL_NS : Int = 86_400_000_000_000;
  private let TOMBSTONE_TTL_NS : Int = 86_400_000_000_000;
  private let RESERVATION_TTL_NS : Int = 300_000_000_000;
  private let LEASE_TIMEOUT_NS : Int = 600_000_000_000;
  // key_1 = production key. test_key_1 is a TEST key: do not use it if you claim confidentiality.
  private let KEY_ID : VetKdKeyId = { curve = #bls12_381_g2; name = "key_1" };
  // MUST equal VETKD_CONTEXT in crypto.ts and the daemon helper.
  private let VETKD_CONTEXT : Blob = Text.encodeUtf8("icfirewall_ibe_v1");
  // key_1 derive costs 26_153_846_153 cycles; unused cycles are refunded.
  private let VETKD_DERIVE_CYCLES : Nat = 27_000_000_000;
  private let MIN_CYCLES_FLOOR : Nat = 60_000_000_000;
  private let TRANSPORT_KEY_BYTES : Nat = 48;
  private let KIND_PROMPT : Nat8 = 1;
  private let KIND_RESULT : Nat8 = 2;

  private let INJECTION_PATTERNS : [Text] = [
    "ignore previous instructions", "ignore all previous", "ignore the above", "ignore prior instructions",
    "disregard previous", "disregard all prior", "disregard your instructions", "forget your instructions",
    "forget all previous", "reveal your system prompt", "print your system prompt", "developer mode",
    "jailbreak", "do anything now"
  ];
  private let DESTRUCTIVE_PATTERNS : [Text] = [
    "rm -rf", "rm -fr", "rm -r -f", "drop database", "drop table", "truncate table", "mkfs", "dd if=",
    "format c:", "> /dev/sda", ":(){", "shred -", "del /f /s"
  ];
  private let PRIVILEGE_PATTERNS : [Text] = [
    "chmod 777", "chmod -r 777", "su root", "su -", "chown root", "setuid", "visudo", "/etc/sudoers"
  ];
  private let STRICT_PATTERNS : [Text] = [
    "pretend to be", "act as if", "system override", "you are now", "bypass safety", "bypass your safety",
    "without any restrictions", "no restrictions"
  ];

  // ---------------------------------------------------------------- stable state (unchanged layout)
  stable var schemaVersion : Nat = 8;
  stable var currentMode : FirewallMode = #Medium;
  stable var initStatus : InitializationState = #Uninitialized;
  stable var totalProcessed : Nat = 0;
  stable var totalBlocked : Nat = 0;
  stable var nextTicketId : Nat = 1;
  stable var nextLeaseCounter : Nat = 1;
  stable var currentRetainedBytes : Nat = 0;
  stable var currentReservedBytes : Nat = 0;
  stable var reservedResultCount : Nat = 0;
  stable var activeReservedPrivateTicketsCount : Nat = 0;
  stable var cachedVetKeyPublicKey : ?Blob = null;
  stable var isFetchingVetKey : Bool = false; // kept only for upgrade compatibility

  stable var masterPrincipal : ?Principal = null;
  stable var daemonPrincipal : ?Principal = null;
  stable var adminPrincipals : [Principal] = [];
  stable var activeReservationCount : Nat = 0;
  stable var activeTicketsCount : Nat = 0;

  stable var stableQueue : [Nat] = [];
  stable var stableTicketStates : [(Nat, TicketState)] = [];
  stable var stableTimestamps : [(Nat, Int)] = [];
  stable var stableResultTimestamps : [(Nat, Int)] = [];
  stable var stableTerminalTimestamps : [(Nat, Int)] = [];
  stable var stableAttemptCounts : [(Nat, Nat)] = [];
  stable var stableTaskPayloads : [(Nat, TaskType)] = [];
  stable var stableResults : [(Nat, Text)] = [];
  stable var stableSubmitters : [(Nat, Principal)] = [];
  stable var stableTransportKeys : [(Nat, Blob)] = []; // legacy, unused
  stable var stableTicketResRecords : [(Nat, TicketReservationRecord)] = [];
  stable var stableRateLimits : [(Principal, Int)] = [];
  stable var stablePrincipalResCounts : [(Principal, Nat)] = [];
  stable var stableThreatLogData : [ThreatEvent] = [];

  stable var securityRulesConfig : SecurityRulesConfig = {
    blockPromptInjection = true; blockDestructiveCommands = true;
    blockPrivilegeEscalation = true; maxContextLength = 12000;
  };

  // new in v8.8 (adding stable vars is upgrade-safe)
  stable var pendingMaster : ?Principal = null;
  stable var stablePrivateTickets : [Nat] = [];

  // ---------------------------------------------------------------- runtime state
  private let promptQueue = Buffer.Buffer<Nat>(16);
  private let ticketStates = RBTree.RBTree<Nat, TicketState>(Nat.compare);
  private let reservationTimestamps = RBTree.RBTree<Nat, Int>(Nat.compare);
  private let resultTimestamps = RBTree.RBTree<Nat, Int>(Nat.compare);
  private let terminalTimestamps = RBTree.RBTree<Nat, Int>(Nat.compare);
  private let attemptCounts = RBTree.RBTree<Nat, Nat>(Nat.compare);
  private let taskPayloads = RBTree.RBTree<Nat, TaskType>(Nat.compare);
  private let resultsMap = RBTree.RBTree<Nat, Text>(Nat.compare);
  private let submittersMap = RBTree.RBTree<Nat, Principal>(Nat.compare);
  private let ticketResRecords = RBTree.RBTree<Nat, TicketReservationRecord>(Nat.compare);
  private let principalRateLimits = RBTree.RBTree<Principal, Int>(Principal.compare);
  private let privateTickets = RBTree.RBTree<Nat, Bool>(Nat.compare);
  private let deriveCounts = RBTree.RBTree<Nat, Nat>(Nat.compare);
  private let principalActive = RBTree.RBTree<Principal, Nat>(Principal.compare);
  private let principalReservationCounts = RBTree.RBTree<Principal, Nat>(Principal.compare);
  private let threatLog = Buffer.Buffer<ThreatEvent>(16);
  private var rateLimitEntries : Nat = 0;

  // ---------------------------------------------------------------- small helpers
  private func sub(a : Nat, b : Nat) : Nat { if (a >= b) { a - b } else { 0 } };

  private func modeName(m : FirewallMode) : Text {
    switch (m) { case (#Off) { "OFF" }; case (#Medium) { "MEDIUM" }; case (#On) { "ON" } }
  };

  private func dump<K, V>(t : RBTree.RBTree<K, V>) : [(K, V)] { Iter.toArray(t.entries()) };
  private func load<K, V>(t : RBTree.RBTree<K, V>, items : [(K, V)]) {
    for ((k, v) in items.vals()) { t.put(k, v) };
  };

  private func ticketIdentity(kind : Nat8, ticket : Nat) : Blob {
    let b = Buffer.Buffer<Nat8>(9);
    b.add(kind);
    var i : Nat = 0;
    while (i < 8) {
      b.add(Nat8.fromNat((ticket / Nat.pow(256, 7 - i)) % 256));
      i += 1;
    };
    Blob.fromArray(Buffer.toArray(b))
  };

  private func parsePrincipal(t : Text) : Principal {
    if (Text.size(t) == 0 or Text.size(t) > 63) { Debug.trap("Error: Invalid principal text."); };
    let p = Principal.fromText(t); // traps on malformed input
    if (Principal.isAnonymous(p)) { Debug.trap("Error: Anonymous principal is not allowed."); };
    p
  };

  private func isMaster(p : Principal) : Bool {
    switch (masterPrincipal) { case (?m) { m == p }; case null { false } }
  };
  private func isAdmin(p : Principal) : Bool {
    for (a in adminPrincipals.vals()) { if (a == p) { return true } };
    false
  };
  private func isAdminOrMaster(p : Principal) : Bool { isMaster(p) or isAdmin(p) };
  private func isDaemon(p : Principal) : Bool {
    switch (daemonPrincipal) { case (?d) { d == p }; case null { false } }
  };
  private func assertDaemon(p : Principal) {
    if (not isDaemon(p)) { Debug.trap("Unauthorized: caller is not the authorized daemon."); };
  };
  private func assertNotAnonymous(p : Principal) {
    if (Principal.isAnonymous(p)) { Debug.trap("Unauthorized: anonymous caller."); };
  };

  private func deny(mode : Text, reason : Text, short : Text) : PromptResult {
    { allowed = false; mode; response = "BLOCKED: " # reason; reason = short; ticketId = null }
  };

  // ---------------------------------------------------------------- per-principal counters
  private func incMap(m : RBTree.RBTree<Principal, Nat>, p : Principal) {
    let cur = switch (m.get(p)) { case (?c) { c }; case null { 0 } };
    m.put(p, cur + 1);
  };
  private func decMap(m : RBTree.RBTree<Principal, Nat>, p : Principal) {
    switch (m.get(p)) {
      case (?c) { if (c > 1) { m.put(p, c - 1) } else { ignore m.remove(p) } };
      case null {};
    };
  };
  private func getCount(m : RBTree.RBTree<Principal, Nat>, p : Principal) : Nat {
    switch (m.get(p)) { case (?c) { c }; case null { 0 } }
  };

  // ---------------------------------------------------------------- reservation accounting (never traps)
  private func releaseReservation(ticket : Nat) {
    switch (ticketResRecords.get(ticket)) {
      case null {};
      case (?rec) {
        if (rec.released) { return };
        if (rec.queueSlotReserved) { activeReservedPrivateTicketsCount := sub(activeReservedPrivateTicketsCount, 1) };
        if (rec.resultCapacityReserved) { reservedResultCount := sub(reservedResultCount, 1) };
        currentReservedBytes := sub(currentReservedBytes, rec.bytesReserved);
        if (rec.principalQuotaReserved) {
          decMap(principalReservationCounts, rec.owner);
          activeReservationCount := sub(activeReservationCount, 1);
        };
        if (rec.activeCounted) {
          activeTicketsCount := sub(activeTicketsCount, 1);
          decMap(principalActive, rec.owner);
        };
        ticketResRecords.put(ticket, {
          rec with queueSlotReserved = false; resultCapacityReserved = false; bytesReserved = 0;
          principalQuotaReserved = false; activeCounted = false; released = true;
        });
      };
    };
  };

  // Moves a ticket into a terminal state and frees everything it held.
  private func finishTicket(ticket : Nat, st : TicketState) {
    ticketStates.put(ticket, st);
    terminalTimestamps.put(ticket, Time.now());
    ignore taskPayloads.remove(ticket);
    ignore attemptCounts.remove(ticket);
    ignore reservationTimestamps.remove(ticket);
    releaseReservation(ticket);
  };

  private func queueContains(ticket : Nat) : Bool {
    for (t in promptQueue.vals()) { if (t == ticket) { return true } };
    false
  };

  // ---------------------------------------------------------------- rate limiting
  private func enforceRateLimit(caller : Principal) : Bool {
    let now = Time.now();
    switch (principalRateLimits.get(caller)) {
      case (?last) { if (now - last < RATE_GAP_NS) { return false } };
      case null {
        if (rateLimitEntries >= 2000) {
          let stale = Buffer.Buffer<Principal>(16);
          for ((p, t) in principalRateLimits.entries()) { if (now - t > 60_000_000_000) { stale.add(p) } };
          for (p in stale.vals()) { ignore principalRateLimits.remove(p); rateLimitEntries := sub(rateLimitEntries, 1) };
          // fail closed only at a hard ceiling, so a flood of fresh principals cannot lock everyone out
          if (rateLimitEntries >= 20000) { return false };
        };
        rateLimitEntries += 1;
      };
    };
    principalRateLimits.put(caller, now);
    true
  };

  // ---------------------------------------------------------------- scanner (inspected prompts only)
  private func isIgnorable(code : Nat32) : Bool {
    (code >= 0x200B and code <= 0x200F) or (code >= 0x202A and code <= 0x202E) or
    (code >= 0x2060 and code <= 0x2064) or code == 0xFEFF or code == 0x00AD or
    (code >= 0xE0000 and code <= 0xE007F)
  };

  // lowercase, drop zero-width / bidi / tag characters, collapse whitespace
  private func normalizeForScan(t : Text) : Text {
    let out = Buffer.Buffer<Char>(64);
    var lastSpace = true;
    for (c in Text.toLowercase(t).chars()) {
      let code = Char.toNat32(c);
      if (not isIgnorable(code)) {
        if (Char.isWhitespace(c) or code == 0x00A0) {
          if (not lastSpace) { out.add(' '); lastSpace := true };
        } else {
          out.add(c);
          lastSpace := false;
        };
      };
    };
    Text.fromIter(out.vals())
  };

  private func wordsOf(norm : Text) : [Text] {
    Iter.toArray(Text.split(norm, #predicate(func (c : Char) : Bool { not (Char.isAlphabetic(c) or Char.isDigit(c)) })))
  };
  private func hasWord(words : [Text], w : Text) : Bool {
    for (x in words.vals()) { if (x == w) { return true } };
    false
  };
  private func hasPattern(norm : Text, patterns : [Text]) : Bool {
    for (p in patterns.vals()) { if (Text.contains(norm, #text p)) { return true } };
    false
  };

  // Heuristic only. Treat it as a speed bump, not a boundary: the daemon must scan again after decryption.
  private func scanForThreats(payload : Text, strict : Bool) : ?(Text, Text) {
    let cfg = securityRulesConfig;
    if (cfg.maxContextLength > 0 and Blob.toArray(Text.encodeUtf8(payload)).size() > cfg.maxContextLength) {
      return ?("Context length exceeded", "MEDIUM");
    };
    let norm = normalizeForScan(payload);
    let words = wordsOf(norm);
    if (cfg.blockPromptInjection and hasPattern(norm, INJECTION_PATTERNS)) { return ?("Prompt injection", "HIGH") };
    if (cfg.blockDestructiveCommands and (hasPattern(norm, DESTRUCTIVE_PATTERNS) or hasWord(words, "mkfs"))) {
      return ?("Destructive command", "CRITICAL");
    };
    if (cfg.blockPrivilegeEscalation and (hasPattern(norm, PRIVILEGE_PATTERNS) or hasWord(words, "sudo") or hasWord(words, "doas"))) {
      return ?("Privilege escalation", "CRITICAL");
    };
    if (strict and hasPattern(norm, STRICT_PATTERNS)) { return ?("Prompt injection (strict)", "HIGH") };
    null
  };

  private func previewText(t : Text, maxLen : Nat) : Text {
    var out = "";
    var n : Nat = 0;
    for (c in t.chars()) {
      if (n >= maxLen) { return out };
      out #= Text.fromChar(c);
      n += 1;
    };
    out
  };

  private func logThreat(threatType : Text, severity : Text, snippet : Text) {
    if (threatLog.size() >= MAX_THREAT_LOG) { ignore threatLog.remove(0) };
    threatLog.add({ timestamp = Time.now(); threatType; severity; snippet });
    totalBlocked += 1;
  };

  // ---------------------------------------------------------------- ownership & roles
  // Step 1 (dfx, controller identity):  proposeMaster("<your II principal>")
  // Step 2 (browser, that II principal): claimMasterPID("<same principal>")
  public shared ({ caller }) func proposeMaster(pidText : Text) : async Text {
    if (caller != installer and not isMaster(caller)) { Debug.trap("Unauthorized: installer or master only."); };
    pendingMaster := ?parsePrincipal(pidText);
    "Pending master set. That principal must now call claimMasterPID."
  };

  public shared ({ caller }) func claimMasterPID(pidText : Text) : async Text {
    assertNotAnonymous(caller);
    if (pidText != Principal.toText(caller)) { return "Error: principal text does not match the caller." };
    switch (pendingMaster) {
      case (?p) {
        if (p != caller) { return "Error: caller is not the proposed master." };
        masterPrincipal := ?caller;
        pendingMaster := null;
        initStatus := #Initialized;
        "Success: Master claimed securely."
      };
      case null { "Error: no pending master. A controller must call proposeMaster first." };
    }
  };

  public shared query ({ caller }) func isMasterClaimed() : async Bool {
    switch (masterPrincipal) { case (?_) { true }; case null { false } }
  };

  public shared query ({ caller }) func getRole() : async Text {
    if (Principal.isAnonymous(caller)) { "anonymous" }
    else if (isMaster(caller)) { "master" }
    else if (isAdmin(caller)) { "admin" }
    else if (isDaemon(caller)) { "daemon" }
    else { "user" }
  };

  public shared ({ caller }) func setDaemonPrincipal(pidText : Text) : async Text {
    if (not isAdminOrMaster(caller)) { Debug.trap("Unauthorized."); };
    let p = parsePrincipal(pidText);
    // separation of duties: the daemon principal must not also be an owner/admin
    if (isAdminOrMaster(p)) { Debug.trap("Error: daemon principal must differ from master/admin principals."); };
    daemonPrincipal := ?p;
    "Daemon principal authorized."
  };

  public shared ({ caller }) func setMode(newModeText : Text) : async Text {
    if (not isAdminOrMaster(caller)) { Debug.trap("Unauthorized."); };
    if (newModeText == "Off") { currentMode := #Off }
    else if (newModeText == "On") { currentMode := #On }
    else if (newModeText == "Medium") { currentMode := #Medium }
    else { Debug.trap("Error: Invalid firewall mode."); };
    "Mode updated."
  };

  public shared ({ caller }) func addAdmin(pidText : Text) : async Text {
    if (not isMaster(caller)) { Debug.trap("Unauthorized: Master only."); };
    let p = parsePrincipal(pidText);
    if (isAdmin(p)) { return "Already an admin." };
    if (isDaemon(p)) { Debug.trap("Error: the daemon principal cannot be an admin."); };
    if (adminPrincipals.size() >= MAX_ADMINS) { Debug.trap("Admin limit reached."); };
    adminPrincipals := Array.append(adminPrincipals, [p]);
    "Admin added."
  };

  public shared ({ caller }) func removeAdmin(pidText : Text) : async Text {
    if (not isMaster(caller)) { Debug.trap("Unauthorized: Master only."); };
    let target = parsePrincipal(pidText);
    adminPrincipals := Array.filter<Principal>(adminPrincipals, func (a : Principal) : Bool { a != target });
    "Admin revoked."
  };

  public shared ({ caller }) func updateSecurityRules(newConfig : SecurityRulesConfig) : async Text {
    if (not isMaster(caller)) { Debug.trap("Unauthorized: Master only."); };
    if (newConfig.maxContextLength != 0 and (newConfig.maxContextLength < 500 or newConfig.maxContextLength > HARD_MAX_PROMPT)) {
      Debug.trap("Error: maxContextLength must be 0 or between 500 and 20000.");
    };
    securityRulesConfig := newConfig;
    "Security rules updated."
  };

  public shared query func getSecurityRules() : async SecurityRulesConfig { securityRulesConfig };

  // ---------------------------------------------------------------- vetKeys
  // Public (verification / IBE-encryption) key for context VETKD_CONTEXT. Free to call; cached.
  public shared ({ caller }) func getVetKeyPublicKey() : async Blob {
    assertNotAnonymous(caller);
    switch (cachedVetKeyPublicKey) {
      case (?pk) { return pk };
      case null {};
    };
    let res = await mgmt.vetkd_public_key({ canister_id = null; context = VETKD_CONTEXT; key_id = KEY_ID });
    cachedVetKeyPublicKey := ?res.public_key;
    res.public_key
  };

  private func checkTransportKey(k : Blob) {
    if (Blob.toArray(k).size() != TRANSPORT_KEY_BYTES) { Debug.trap("Error: transport public key must be 48 bytes (BLS12-381 G1)."); };
  };
  private func requireCyclesFloor() {
    if (Cycles.balance() < MIN_CYCLES_FLOOR) { Debug.trap("Error: canister cycle balance too low for key derivation."); };
  };
  private func bumpDerive(ticket : Nat) {
    let n = switch (deriveCounts.get(ticket)) { case (?c) { c }; case null { 0 } };
    if (n >= MAX_DERIVES_PER_TICKET) { Debug.trap("Error: key derivation limit reached for this ticket."); };
    deriveCounts.put(ticket, n + 1);
  };

  private func daemonLeaseValid(ticket : Nat, lease : Nat) : Bool {
    switch (ticketStates.get(ticket)) {
      case (?#Processing(t, tok)) {
        let isPrivate = switch (taskPayloads.get(ticket)) { case (?#Private(_)) { true }; case _ { false } };
        tok == lease and (Time.now() - t) <= LEASE_TIMEOUT_NS and isPrivate
      };
      case _ { false };
    }
  };

  // Daemon: key that decrypts the PROMPT of a ticket it currently holds a lease on.
  public shared ({ caller }) func deriveDaemonKey(ticketId : Nat, leaseToken : Nat, transportPublicKey : Blob) : async Blob {
    assertDaemon(caller);
    checkTransportKey(transportPublicKey);
    requireCyclesFloor();
    if (not daemonLeaseValid(ticketId, leaseToken)) { Debug.trap("Error: ticket is not under a valid private lease."); };
    bumpDerive(ticketId);
    Cycles.add<system>(VETKD_DERIVE_CYCLES);
    let res = await mgmt.vetkd_derive_key({
      input = ticketIdentity(KIND_PROMPT, ticketId);
      context = VETKD_CONTEXT;
      transport_public_key = transportPublicKey;
      key_id = KEY_ID;
    });
    if (not daemonLeaseValid(ticketId, leaseToken)) { Debug.trap("Error: lease changed during derivation."); };
    res.encrypted_key
  };

  // Submitter: key that decrypts the RESULT of their own completed private ticket.
  public shared ({ caller }) func deriveResultKey(ticketId : Nat, transportPublicKey : Blob) : async Blob {
    assertNotAnonymous(caller);
    checkTransportKey(transportPublicKey);
    requireCyclesFloor();
    let owner = switch (submittersMap.get(ticketId)) { case (?s) { s == caller }; case null { false } };
    let completed = switch (ticketStates.get(ticketId)) { case (?#Completed) { true }; case _ { false } };
    let isPrivate = switch (privateTickets.get(ticketId)) { case (?_) { true }; case null { false } };
    if (not (owner and completed and isPrivate)) { Debug.trap("Error: not your completed private ticket."); };
    bumpDerive(ticketId);
    Cycles.add<system>(VETKD_DERIVE_CYCLES);
    let res = await mgmt.vetkd_derive_key({
      input = ticketIdentity(KIND_RESULT, ticketId);
      context = VETKD_CONTEXT;
      transport_public_key = transportPublicKey;
      key_id = KEY_ID;
    });
    res.encrypted_key
  };

  // ---------------------------------------------------------------- private tickets
  public shared ({ caller }) func reservePrivateTicket() : async Nat {
    assertNotAnonymous(caller);
    if (currentMode == #On) { Debug.trap("Error: firewall is in lockdown (mode On); private tickets are disabled."); };
    if (not enforceRateLimit(caller)) { Debug.trap("Rate limited."); };
    if (Iter.size(resultsMap.entries()) + reservedResultCount >= MAX_RETAINED_RESULTS or
        (currentRetainedBytes + currentReservedBytes + EXPECTED_MAX_RESPONSE_BYTES) > MAX_RETAINED_BYTES) {
      Debug.trap("Error: result storage capacity reached.");
    };
    if (getCount(principalReservationCounts, caller) >= MAX_PRINCIPAL_RESERVATIONS or
        getCount(principalActive, caller) >= MAX_PRINCIPAL_ACTIVE or
        activeReservationCount >= MAX_GLOBAL_RESERVATIONS or
        activeTicketsCount >= MAX_ACTIVE_TICKETS or
        promptQueue.size() + activeReservedPrivateTicketsCount >= MAX_QUEUE_LIMIT) {
      Debug.trap("Error: reservation quota or queue capacity reached.");
    };
    let tid = nextTicketId;
    nextTicketId += 1;
    submittersMap.put(tid, caller);
    ticketStates.put(tid, #Reserved);
    reservationTimestamps.put(tid, Time.now());
    ticketResRecords.put(tid, {
      owner = caller; queueSlotReserved = true; resultCapacityReserved = true;
      bytesReserved = EXPECTED_MAX_RESPONSE_BYTES; principalQuotaReserved = true;
      activeCounted = true; released = false;
    });
    currentReservedBytes += EXPECTED_MAX_RESPONSE_BYTES;
    reservedResultCount += 1;
    activeReservedPrivateTicketsCount += 1;
    activeReservationCount += 1;
    activeTicketsCount += 1;
    incMap(principalReservationCounts, caller);
    incMap(principalActive, caller);
    tid
  };

  public shared ({ caller }) func submitPrivate(ticketId : Nat, ciphertext : Blob) : async PromptResult {
    let mode = modeName(currentMode);
    if (currentMode == #On) { return deny(mode, "lockdown: private tickets are disabled", "Lockdown") };
    let rec = switch (ticketResRecords.get(ticketId)) {
      case (?r) { r };
      case null { Debug.trap("Error: ticket does not exist."); };
    };
    if (rec.owner != caller) { Debug.trap("Unauthorized owner."); };
    if (rec.released or not rec.queueSlotReserved or not rec.principalQuotaReserved) { Debug.trap("Error: reservation no longer valid."); };
    switch (ticketStates.get(ticketId)) { case (?#Reserved) {}; case _ { Debug.trap("Error: invalid ticket state."); } };
    switch (reservationTimestamps.get(ticketId)) {
      case (?t) { if (Time.now() - t > RESERVATION_TTL_NS) { Debug.trap("Error: reservation expired."); } };
      case null { Debug.trap("Error: missing reservation timestamp."); };
    };
    let size = Blob.toArray(ciphertext).size();
    if (size == 0 or size > MAX_CIPHERTEXT_BYTES) { Debug.trap("Error: ciphertext size out of range."); };
    if (promptQueue.size() >= MAX_QUEUE_LIMIT) { Debug.trap("Error: queue full."); };

    // the reserved slot becomes a real queue entry; the per-principal reservation is released
    activeReservedPrivateTicketsCount := sub(activeReservedPrivateTicketsCount, 1);
    decMap(principalReservationCounts, caller);
    activeReservationCount := sub(activeReservationCount, 1);
    ticketResRecords.put(ticketId, { rec with queueSlotReserved = false; principalQuotaReserved = false });
    taskPayloads.put(ticketId, #Private(ciphertext));
    privateTickets.put(ticketId, true);
    ticketStates.put(ticketId, #Submitted);
    promptQueue.add(ticketId);
    totalProcessed += 1;
    { allowed = true; mode; response = "QUEUED"; reason = "Private ticket stored; not scanned by the canister"; ticketId = ?ticketId }
  };

  // ---------------------------------------------------------------- inspected prompts
  public shared ({ caller }) func processPrompt(textBody : Text) : async PromptResult {
    let mode = modeName(currentMode);
    if (Principal.isAnonymous(caller)) { return deny(mode, "anonymous callers are not allowed", "Anonymous") };
    if (not enforceRateLimit(caller)) { return deny(mode, "rate limited", "Rate Limit") };
    if (Blob.toArray(Text.encodeUtf8(textBody)).size() > HARD_MAX_PROMPT) { return deny(mode, "prompt exceeds the hard size limit", "Size Limit") };
    if (Iter.size(resultsMap.entries()) + reservedResultCount >= MAX_RETAINED_RESULTS or
        (currentRetainedBytes + currentReservedBytes + EXPECTED_MAX_RESPONSE_BYTES) > MAX_RETAINED_BYTES) {
      return deny(mode, "result storage capacity reached", "Capacity");
    };
    if (promptQueue.size() + activeReservedPrivateTicketsCount >= MAX_QUEUE_LIMIT or
        activeTicketsCount >= MAX_ACTIVE_TICKETS or
        getCount(principalActive, caller) >= MAX_PRINCIPAL_ACTIVE) {
      return deny(mode, "queue or per-user limit reached", "Capacity");
    };

    let scan = switch (currentMode) {
      case (#On) { scanForThreats(textBody, true) };
      case (#Medium) { scanForThreats(textBody, false) };
      case (#Off) { null };
    };
    switch (scan) {
      case (?(threat, severity)) {
        logThreat(threat, severity, previewText(textBody, 40));
        return deny(mode, threat, threat);
      };
      case null {};
    };

    let tid = nextTicketId;
    nextTicketId += 1;
    submittersMap.put(tid, caller);
    ticketStates.put(tid, #Submitted);
    taskPayloads.put(tid, #Inspected(textBody));
    ticketResRecords.put(tid, {
      owner = caller; queueSlotReserved = false; resultCapacityReserved = true;
      bytesReserved = EXPECTED_MAX_RESPONSE_BYTES; principalQuotaReserved = false;
      activeCounted = true; released = false;
    });
    currentReservedBytes += EXPECTED_MAX_RESPONSE_BYTES;
    reservedResultCount += 1;
    activeTicketsCount += 1;
    incMap(principalActive, caller);
    promptQueue.add(tid);
    totalProcessed += 1;
    { allowed = true; mode; response = "QUEUED"; reason = "Passed heuristic scan"; ticketId = ?tid }
  };

  // ---------------------------------------------------------------- daemon API (lease protocol)
  public shared ({ caller }) func getPendingPrompt() : async ?PendingTask {
    assertDaemon(caller);
    while (promptQueue.size() > 0) {
      let ticket = promptQueue.get(0);
      ignore promptQueue.remove(0);
      let submitted = switch (ticketStates.get(ticket)) { case (?#Submitted) { true }; case _ { false } };
      if (submitted) {
        switch (taskPayloads.get(ticket)) {
          case (?payload) {
            let token = nextLeaseCounter;
            nextLeaseCounter += 1;
            let att = switch (attemptCounts.get(ticket)) { case (?a) { a + 1 }; case null { 1 } };
            attemptCounts.put(ticket, att);
            ticketStates.put(ticket, #Processing(Time.now(), token));
            return ?{ ticketId = ticket; taskType = payload; leaseToken = token; attemptCount = att };
          };
          case null { finishTicket(ticket, #DeadLetter) };
        };
      };
    };
    null
  };

  private func leaseCheck(ticket : Nat, lease : Nat) : ?Text {
    switch (ticketStates.get(ticket)) {
      case (?#Processing(t, tok)) {
        if (tok != lease) { return ?"Error: stale lease token." };
        if (Time.now() - t > LEASE_TIMEOUT_NS) { return ?"Error: lease expired." };
        null
      };
      case _ { ?"Error: ticket is not under lease." };
    }
  };

  private func saveResultInternal(caller : Principal, ticket : Nat, lease : Nat, responseText : Text, expectPrivate : Bool) : Text {
    assertDaemon(caller);
    switch (leaseCheck(ticket, lease)) { case (?err) { return err }; case null {} };
    let isPrivate = switch (taskPayloads.get(ticket)) {
      case (?#Private(_)) { true };
      case (?#Inspected(_)) { false };
      case null { return "Error: task payload missing." };
    };
    if (isPrivate != expectPrivate) { return "Error: task type mismatch." };
    let size = Blob.toArray(Text.encodeUtf8(responseText)).size();
    if (size > EXPECTED_MAX_RESPONSE_BYTES) { return "Error: result exceeds 64 KB." };
    if (currentRetainedBytes + size > MAX_RETAINED_BYTES) { return "Error: global result storage full." };

    let now = Time.now();
    resultsMap.put(ticket, responseText);
    resultTimestamps.put(ticket, now);
    currentRetainedBytes += size;
    ticketStates.put(ticket, #Completed);
    terminalTimestamps.put(ticket, now);
    ignore taskPayloads.remove(ticket);
    ignore attemptCounts.remove(ticket);
    releaseReservation(ticket);
    "Saved"
  };

  public shared ({ caller }) func savePrivateResult(ticket : Nat, leaseToken : Nat, sealedResult : Text) : async Text {
    saveResultInternal(caller, ticket, leaseToken, sealedResult, true)
  };
  public shared ({ caller }) func saveInspectedResult(ticket : Nat, leaseToken : Nat, plaintextResponse : Text) : async Text {
    saveResultInternal(caller, ticket, leaseToken, plaintextResponse, false)
  };

  // The daemon reports a failed attempt instead of storing a fake "success".
  public shared ({ caller }) func reportFailure(ticket : Nat, leaseToken : Nat, reason : Text) : async Text {
    assertDaemon(caller);
    switch (leaseCheck(ticket, leaseToken)) { case (?err) { return err }; case null {} };
    retryOrDead(ticket);
    "Failure recorded."
  };

  private func retryOrDead(ticket : Nat) {
    let att = switch (attemptCounts.get(ticket)) { case (?a) { a }; case null { 1 } };
    if (att >= MAX_RETRY_COUNT) {
      finishTicket(ticket, #DeadLetter);
    } else {
      ticketStates.put(ticket, #Submitted);
      if (not queueContains(ticket)) { promptQueue.add(ticket) };
    };
  };

  // ---------------------------------------------------------------- reads
  public shared query ({ caller }) func checkResponse(ticket : Nat) : async ?Text {
    switch (submittersMap.get(ticket)) {
      case (?s) { if (s == caller) { return resultsMap.get(ticket) } };
      case null {};
    };
    null
  };

  public shared query ({ caller }) func getTicketStatus(ticket : Nat) : async ?Text {
    switch (submittersMap.get(ticket)) {
      case (?s) {
        if (s != caller) { return null };
        switch (ticketStates.get(ticket)) {
          case (?#Reserved) { ?"reserved" };
          case (?#Submitted) { ?"queued" };
          case (?#Processing(_, _)) { ?"processing" };
          case (?#Completed) { ?"completed" };
          case (?#DeadLetter) { ?"failed" };
          case (?#Expired) { ?"expired" };
          case null { null };
        }
      };
      case null { null };
    }
  };

  public query func getStats() : async SystemStats {
    {
      mode = modeName(currentMode);
      totalProcessed; totalBlocked;
      activeQueueLength = promptQueue.size();
      adminCount = adminPrincipals.size();
      masterPid = "Restricted"; daemonPid = "Restricted";
    }
  };

  public shared query ({ caller }) func checkIsAdmin(pidText : Text) : async Bool {
    if (not isAdminOrMaster(caller)) { return false };
    isAdminOrMaster(Principal.fromText(pidText))
  };

  public shared query ({ caller }) func getAdmins() : async [Text] {
    if (not isMaster(caller)) { return [] };
    Array.map<Principal, Text>(adminPrincipals, func (p : Principal) : Text { Principal.toText(p) })
  };

  public shared query ({ caller }) func getMasterPID() : async Text {
    if (not isAdminOrMaster(caller)) { return "Unauthorized" };
    switch (masterPrincipal) { case (?p) { Principal.toText(p) }; case null { "Unassigned" } }
  };

  public shared query ({ caller }) func getDaemonPID() : async Text {
    if (not isAdminOrMaster(caller)) { return "Unauthorized" };
    switch (daemonPrincipal) { case (?p) { Principal.toText(p) }; case null { "Unassigned" } }
  };

  public shared query ({ caller }) func getThreats() : async [ThreatEvent] {
    if (not isAdminOrMaster(caller)) { return [] };
    Buffer.toArray(threatLog)
  };

  // ---------------------------------------------------------------- cleanup
  private func tombstoneExpired(ticket : Nat, now : Int) : Bool {
    switch (terminalTimestamps.get(ticket)) {
      case (?t) { now - t > TOMBSTONE_TTL_NS };
      case null { terminalTimestamps.put(ticket, now); false };
    }
  };

  private func runCleanup() {
    let now = Time.now();
    let expiredRes = Buffer.Buffer<Nat>(8);
    let timedOut = Buffer.Buffer<Nat>(8);
    let expiredResults = Buffer.Buffer<Nat>(8);
    let purge = Buffer.Buffer<Nat>(8);

    for ((ticket, state) in ticketStates.entries()) {
      switch (state) {
        case (#Reserved) {
          let fresh = switch (reservationTimestamps.get(ticket)) { case (?t) { now - t <= RESERVATION_TTL_NS }; case null { false } };
          if (not fresh) { expiredRes.add(ticket) };
        };
        case (#Processing(t, _)) { if (now - t > LEASE_TIMEOUT_NS) { timedOut.add(ticket) } };
        case (#Completed) {
          switch (resultTimestamps.get(ticket)) {
            case (?t) { if (now - t > RESULT_TTL_NS) { expiredResults.add(ticket) } };
            case null { expiredResults.add(ticket) };
          };
        };
        case (#Expired) { if (tombstoneExpired(ticket, now)) { purge.add(ticket) } };
        case (#DeadLetter) { if (tombstoneExpired(ticket, now)) { purge.add(ticket) } };
        case (#Submitted) {};
      };
    };

    for (t in expiredRes.vals()) { finishTicket(t, #Expired) };
    for (t in timedOut.vals()) { retryOrDead(t) };
    for (t in expiredResults.vals()) {
      switch (resultsMap.remove(t)) {
        case (?txt) { currentRetainedBytes := sub(currentRetainedBytes, Blob.toArray(Text.encodeUtf8(txt)).size()) };
        case null {};
      };
      ignore resultTimestamps.remove(t);
      ticketStates.put(t, #Expired);
      terminalTimestamps.put(t, now);
    };
    for (t in purge.vals()) {
      ignore ticketStates.remove(t);
      ignore terminalTimestamps.remove(t);
      ignore submittersMap.remove(t);
      ignore attemptCounts.remove(t);
      ignore taskPayloads.remove(t);
      ignore reservationTimestamps.remove(t);
      ignore resultTimestamps.remove(t);
      ignore ticketResRecords.remove(t);
      ignore privateTickets.remove(t);
      ignore deriveCounts.remove(t);
      switch (resultsMap.remove(t)) {
        case (?txt) { currentRetainedBytes := sub(currentRetainedBytes, Blob.toArray(Text.encodeUtf8(txt)).size()) };
        case null {};
      };
    };
  };

  // ---------------------------------------------------------------- upgrade hooks
  system func preupgrade() {
    stableQueue := Buffer.toArray(promptQueue);
    stableTicketStates := dump(ticketStates);
    stableTimestamps := dump(reservationTimestamps);
    stableResultTimestamps := dump(resultTimestamps);
    stableTerminalTimestamps := dump(terminalTimestamps);
    stableAttemptCounts := dump(attemptCounts);
    stableTaskPayloads := dump(taskPayloads);
    stableResults := dump(resultsMap);
    stableSubmitters := dump(submittersMap);
    stableTicketResRecords := dump(ticketResRecords);
    stableRateLimits := dump(principalRateLimits);
    stablePrincipalResCounts := dump(principalReservationCounts);
    stableThreatLogData := Buffer.toArray(threatLog);
    stablePrivateTickets := Array.map<(Nat, Bool), Nat>(dump(privateTickets), func (e : (Nat, Bool)) : Nat { e.0 });
  };

  system func postupgrade() {
    load(ticketStates, stableTicketStates);
    load(reservationTimestamps, stableTimestamps);
    load(resultTimestamps, stableResultTimestamps);
    load(terminalTimestamps, stableTerminalTimestamps);
    load(attemptCounts, stableAttemptCounts);
    load(taskPayloads, stableTaskPayloads);
    load(resultsMap, stableResults);
    load(submittersMap, stableSubmitters);
    load(ticketResRecords, stableTicketResRecords);
    load(principalRateLimits, stableRateLimits);
    rateLimitEntries := Iter.size(principalRateLimits.entries());
    for (t in stablePrivateTickets.vals()) { privateTickets.put(t, true) };
    for (ev in stableThreatLogData.vals()) { threatLog.add(ev) };

    cachedVetKeyPublicKey := null;
    isFetchingVetKey := false;
    if (initStatus == #Initializing) { initStatus := #Uninitialized };
    switch (masterPrincipal) { case (?_) { initStatus := #Initialized }; case null {} };

    var rb : Nat = 0; var rc : Nat = 0; var arc : Nat = 0; var atc : Nat = 0; var aprq : Nat = 0;
    for ((_, rec) in ticketResRecords.entries()) {
      if (not rec.released) {
        rb += rec.bytesReserved;
        if (rec.resultCapacityReserved) { rc += 1 };
        if (rec.queueSlotReserved) { aprq += 1 };
        if (rec.principalQuotaReserved) { arc += 1; incMap(principalReservationCounts, rec.owner) };
        if (rec.activeCounted) { atc += 1; incMap(principalActive, rec.owner) };
      };
    };
    currentReservedBytes := rb;
    reservedResultCount := rc;
    activeReservationCount := arc;
    activeTicketsCount := atc;
    activeReservedPrivateTicketsCount := aprq;
    var retained : Nat = 0;
    for ((_, txt) in resultsMap.entries()) { retained += Blob.toArray(Text.encodeUtf8(txt)).size() };
    currentRetainedBytes := retained;

    let broken = Buffer.Buffer<Nat>(4);
    for ((t, st) in ticketStates.entries()) {
      switch (st) {
        case (#Submitted) {
          switch (taskPayloads.get(t)) {
            case (?_) { promptQueue.add(t) };
            case null { broken.add(t) };
          };
        };
        case _ {};
      };
    };
    for (t in broken.vals()) { finishTicket(t, #DeadLetter) };

    stableQueue := []; stableTicketStates := []; stableTimestamps := []; stableResultTimestamps := [];
    stableTerminalTimestamps := []; stableAttemptCounts := []; stableTaskPayloads := []; stableResults := [];
    stableSubmitters := []; stableTicketResRecords := []; stableRateLimits := []; stablePrincipalResCounts := [];
    stableThreatLogData := []; stablePrivateTickets := []; stableTransportKeys := [];
  };

  private let _cleanupTimer : Timer.TimerId = Timer.recurringTimer<system>(
    #seconds 300,
    func () : async () { runCleanup() }
  );
};
