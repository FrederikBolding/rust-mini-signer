use primitive_types::U256;
use std::str::FromStr;
mod signer;

use signer::{Signer, Type2Transaction};

fn main() {
    // Test private key - not worth anything :)
    let private_key = "eaf2c50dfd10524651e7e459c1286f0c2404eb0f34ffd2a1eb14373db49fceb6";
    let signer = Signer::new(private_key.to_string());
    let tx = Type2Transaction {
        chain_id: U256::from_str("0x03").unwrap(),
        nonce: U256::from_str("0x06").unwrap(),
        max_priority_fee_per_gas: U256::from_str("0x3b9aca00").unwrap(),
        max_fee_per_gas: U256::from_str("0x4a817c800").unwrap(),
        gas_limit: U256::from_str("0x5208").unwrap(),
        to: U256::from_str("0xB2BB2b958aFA2e96dAb3F3Ce7162B87dAea39017").unwrap(),
        value: U256::from_str("0x2386f26fc10000").unwrap(),
        data: U256::from_str("0x").unwrap(),
        access_list: U256::from_str("0x").unwrap(),
    };
    let sig = signer.sign_type2_tx(tx);
    println!("{}", sig);
    assert_eq!(sig, "02f8720306843b9aca008504a817c80082520894b2bb2b958afa2e96dab3f3ce7162b87daea39017872386f26fc1000080c001a0884850dc596eac6b74175d2c62deedd9295570808882b0cd9adf47e5ac8b3b3da068881b0ef002d48ef78374d6842ee4987a222a4726af47b5a0a4bcb8f38e2cf3")
}
