// Stateless vetKeys helper for the Python daemon. Reads ONE JSON object on stdin, writes ONE JSON object on stdout.
// It does crypto only: no network, no identity. The daemon talks to the canister through dfx.
import {
  DerivedPublicKey,
  EncryptedVetKey,
  IbeCiphertext,
  IbeIdentity,
  IbeSeed,
  TransportSecretKey,
} from '@icp-sdk/vetkeys';

const KIND_PROMPT = 1;
const KIND_RESULT = 2;

const hex = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const toHex = (u8) => Buffer.from(u8).toString('hex');

function identity(kind, ticket) {
  const out = new Uint8Array(9);
  out[0] = kind;
  new DataView(out.buffer).setBigUint64(1, BigInt(ticket), false);
  return out;
}

function readStdin() {
  return new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => (data += c));
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', reject);
  });
}

// Helper to safely instantiate TransportSecretKey across SDK version discrepancies
async function getTransportSecretKey(seedBytes) {
  if (typeof TransportSecretKey.fromSeed === 'function') {
    return TransportSecretKey.fromSeed(seedBytes);
  }
  if (typeof TransportSecretKey.generate === 'function') {
    // Fallback if generate is used or constructor takes seed directly
    return TransportSecretKey.generate(seedBytes);
  }
  // Fallback direct instantiation if supported by current version
  return new TransportSecretKey(seedBytes);
}

try {
  const req = JSON.parse(await readStdin());
  let res;
  if (req.cmd === 'tpk') {
    const tsk = await getTransportSecretKey(hex(req.seed));
    res = { tpk: toHex(tsk.publicKeyBytes()) };
  } else if (req.cmd === 'decrypt') {
    const tsk = await getTransportSecretKey(hex(req.seed));
    const publicKey = DerivedPublicKey.deserialize(hex(req.publicKey));
    const vetKey = EncryptedVetKey.deserialize(hex(req.encryptedKey)).decryptAndVerify(
      tsk,
      publicKey,
      identity(KIND_PROMPT, req.ticket),
    );
    const pt = IbeCiphertext.deserialize(hex(req.ciphertext)).decrypt(vetKey);
    res = { plaintext: new TextDecoder().decode(pt) };
  } else if (req.cmd === 'encrypt') {
    const publicKey = DerivedPublicKey.deserialize(hex(req.publicKey));
    const ct = IbeCiphertext.encrypt(
      publicKey,
      IbeIdentity.fromBytes(identity(KIND_RESULT, req.ticket)),
      new TextEncoder().encode(req.plaintext),
      IbeSeed.random(),
    );
    res = { ciphertext: Buffer.from(ct.serialize()).toString('base64') };
  } else {
    throw new Error('unknown cmd');
  }
  process.stdout.write(JSON.stringify(res));
} catch (e) {
  process.stderr.write(String(e && e.stack ? e.stack : e));
  process.exit(1);
}
