// ICfirewall v8.8: ticket-scoped vetKeys IBE (client side).
//
// Identity layout MUST match main.mo and the daemon helper:
//     identity = kind (1 byte) || ticketId (8 bytes, big-endian)
//     kind 1 = prompt key (daemon only), kind 2 = result key (submitter only)
// Context string MUST equal VETKD_CONTEXT in main.mo.
//
// Flow:
//   submit : IbeCiphertext.encrypt(publicKey, identity(1, ticket), prompt)       -> canister -> daemon decrypts
//   receive: daemon IBE-encrypts the reply to identity(2, ticket); the submitter calls deriveResultKey with a
//            fresh TransportSecretKey, verifies/decrypts the vetKey, then IBE-decrypts the reply.
// Nothing is derived from, or stored in, sessionStorage, and there is no shared AES key.
import {
  DerivedPublicKey,
  EncryptedVetKey,
  IbeCiphertext,
  IbeIdentity,
  IbeSeed,
  TransportSecretKey,
} from '@icp-sdk/vetkeys';

export const KIND_PROMPT = 1;
export const KIND_RESULT = 2;

export function ticketIdentityBytes(kind: number, ticketId: bigint): Uint8Array {
  const out = new Uint8Array(9);
  out[0] = kind;
  new DataView(out.buffer).setBigUint64(1, ticketId, false); // big-endian
  return out;
}

export function bytesToB64(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(s);
}

export function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Encrypt a prompt so only the daemon, holding a live lease on this ticket, can read it. */
export function encryptPrompt(publicKeyBytes: Uint8Array, ticketId: bigint, plaintext: string): Uint8Array {
  if (!publicKeyBytes || publicKeyBytes.length === 0) {
    throw new Error('vetKD public key is empty; cannot encrypt.');
  }
  const publicKey = DerivedPublicKey.deserialize(publicKeyBytes);
  const identity = IbeIdentity.fromBytes(ticketIdentityBytes(KIND_PROMPT, ticketId));
  const ct = IbeCiphertext.encrypt(publicKey, identity, new TextEncoder().encode(plaintext), IbeSeed.random());
  return ct.serialize();
}

/** Decrypt a sealed result. `encryptedVetKey` is the reply of deriveResultKey(ticket, tsk.publicKeyBytes()). */
export function decryptResult(
  publicKeyBytes: Uint8Array,
  encryptedVetKey: Uint8Array,
  ticketId: bigint,
  tsk: TransportSecretKey,
  sealedCiphertext: Uint8Array,
): string {
  const publicKey = DerivedPublicKey.deserialize(publicKeyBytes);
  const vetKey = EncryptedVetKey.deserialize(encryptedVetKey).decryptAndVerify(
    tsk,
    publicKey,
    ticketIdentityBytes(KIND_RESULT, ticketId),
  );
  const plaintext = IbeCiphertext.deserialize(sealedCiphertext).decrypt(vetKey);
  return new TextDecoder().decode(plaintext);
}

export { TransportSecretKey };
