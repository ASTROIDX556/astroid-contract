import re

with open("contracts/multisig/src/test.rs", "r") as f:
    text = f.read()

# Replace Map imports
text = text.replace("soroban_sdk::{symbol_short, Address, Bytes, Env, Vec}", "soroban_sdk::{symbol_short, Address, Bytes, Env, Map}")

# Replace harness setup
setup_old = """fn setup(n: u32, threshold: u32) -> Harness {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, MultiSigContract);
    let client = MultiSigContractClient::new(&env, &contract_id);

    let mut signers = std::vec::Vec::new();
    let mut sv = Vec::new(&env);
    for _ in 0..n {
        let a = Address::generate(&env);
        sv.push_back(a.clone());
        signers.push(a);
    }
    client.initialize(&sv, &threshold);
    Harness {
        env,
        client,
        signers,
    }
}"""
setup_new = """fn setup(weights: std::vec::Vec<u32>, threshold: u32) -> Harness {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, MultiSigContract);
    let client = MultiSigContractClient::new(&env, &contract_id);

    let mut signers = std::vec::Vec::new();
    let mut sm = Map::new(&env);
    for weight in weights {
        let a = Address::generate(&env);
        sm.set(a.clone(), weight);
        signers.push(a);
    }
    client.initialize(&sm, &threshold);
    Harness {
        env,
        client,
        signers,
    }
}"""
text = text.replace(setup_old, setup_new)

# Find all occurrences of setup(n, threshold) and replace with setup(vec![1,1,1..], threshold)
text = re.sub(r"setup\(3, 2\)", "setup(std::vec![1, 1, 1], 2)", text)
text = re.sub(r"setup\(2, 2\)", "setup(std::vec![1, 1], 2)", text)

# For bad_threshold_rejected_on_init
bad_threshold_old = """    let mut sv = Vec::new(&env);
    sv.push_back(Address::generate(&env));
    sv.push_back(Address::generate(&env));
    // threshold 3 > 2 signers
    let res = client.try_initialize(&sv, &3);"""
bad_threshold_new = """    let mut sm = Map::new(&env);
    sm.set(Address::generate(&env), 1);
    sm.set(Address::generate(&env), 1);
    // threshold 3 > 2 signers
    let res = client.try_initialize(&sm, &3);"""
text = text.replace(bad_threshold_old, bad_threshold_new)

# add_and_remove_signer tests `try_add_signer`
text = re.sub(r"try_add_signer\(&h\.signers\[0\], &h\.signers\[1\]\)", "try_add_signer(&h.signers[0], &h.signers[1], &1)", text)
text = re.sub(r"try_add_signer\(&stranger, &extra\)", "try_add_signer(&stranger, &extra, &1)", text)
text = re.sub(r"add_signer\(&h\.signers\[0\], &new_signer\)", "add_signer(&h.signers[0], &new_signer, &1)", text)
text = re.sub(r"assert_eq!\(h\.client\.get_signers\(\)\.len\(\), 4\);", "assert_eq!(h.client.get_signers().keys().len(), 4);", text)

# initialize_state
text = re.sub(r"assert_eq!\(h\.client\.get_signers\(\)\.len\(\), 3\);", "assert_eq!(h.client.get_signers().keys().len(), 3);", text)

# We need a new test for the dynamic weight testing logic!
new_test = """
#[test]
fn execute_dynamic_weights() {
    let h = setup(std::vec![50, 30, 30], 80);
    // Signer 0 has 50 weight. Signer 1 has 30 weight. Signer 2 has 30 weight.
    let id = h.client.propose(
        &h.signers[1], // weight 30
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    // Only proposer's approval (30) < threshold (80).
    let res = h.client.try_execute(&h.signers[1], &id);
    assert_eq!(res, Err(Ok(Error::ThresholdNotMet)));

    h.client.approve(&h.signers[2], &id);
    // 30 + 30 = 60 < 80
    let res2 = h.client.try_execute(&h.signers[1], &id);
    assert_eq!(res2, Err(Ok(Error::ThresholdNotMet)));

    h.client.approve(&h.signers[0], &id);
    // 60 + 50 = 110 >= 80 -> succeeds!
    h.client.execute(&h.signers[0], &id);
    assert!(h.client.get_proposal(&id).executed);
}
"""

text += new_test

with open("contracts/multisig/src/test.rs", "w") as f:
    f.write(text)
