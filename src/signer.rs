use primitive_types::U256;
use rlp::RlpStream;
use secp256k1::recovery::SecretKey;
use secp256k1::{Message, Secp256k1};
use std::str::FromStr;
use tiny_keccak::{Hasher, Keccak};

pub struct Signature {
    pub v: u64,
    pub r: U256,
    pub s: U256,
}

pub struct Type2Transaction {
    pub chain_id: U256,
    pub nonce: U256,
    pub max_priority_fee_per_gas: U256,
    pub max_fee_per_gas: U256,
    pub gas_limit: U256,
    pub to: U256,
    pub value: U256,
    pub data: U256,
    pub access_list: U256,
}

pub struct Signer {
    private_key: SecretKey,
}

impl Signer {
    pub fn new(private_key: String) -> Signer {
        Signer {
            private_key: SecretKey::from_str(&private_key).unwrap(),
        }
    }

    pub fn sign_type2_tx(&self, tx: Type2Transaction) -> String {
        let to_sign = serialize_type2_tx(&tx, None);
        let sig = sign(self.private_key, to_sign.as_ref());
        return hex::encode(serialize_type2_tx(&tx, Some(sig)));
    }
}

fn rlp_append_signature(stream: &mut RlpStream, sig: Signature) {
    stream.append(&sig.v);
    stream.append(&sig.r);
    stream.append(&sig.s);
}

fn serialize_type2_tx(tx: &Type2Transaction, sig: Option<Signature>) -> Vec<u8> {
    let mut stream = RlpStream::new();

    stream.begin_list(if sig.is_some() { 12 } else { 9 });

    stream.append(&tx.chain_id);
    stream.append(&tx.nonce);
    stream.append(&tx.max_priority_fee_per_gas);
    stream.append(&tx.max_fee_per_gas);
    stream.append(&tx.gas_limit);
    stream.append(&tx.to);
    stream.append(&tx.value);
    stream.append(&tx.data);

    // Dont serialize Access List right now
    stream.begin_list(0);

    if let Some(sig) = sig {
        rlp_append_signature(&mut stream, sig);
    }

    return [&[2 as u8], stream.as_raw()].concat();
}

fn sign(private_key: SecretKey, msg: &[u8]) -> Signature {
    let hashed = keccak256(msg);
    let secp = Secp256k1::new();
    let msg = Message::from_slice(&hashed).unwrap();
    let signed = secp.sign_recoverable(&msg, &private_key);
    let (recovery, sig) = signed.serialize_compact();
    return Signature {
        v: recovery.to_i32() as u64,
        r: U256::from_big_endian(&sig[..32]),
        s: U256::from_big_endian(&sig[32..]),
    };
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    return output;
}
