//! Multi-currency balance accounting for SAC + native XLM.
//!
//! Unified, overflow-safe helpers that replace duplicated bookkeeping in the
//! wallet, treasury and escrow contracts. Every amount is an `i128` in the
//! token's smallest unit (stroops for XLM). All arithmetic goes through the
//! shared checked helpers so a wrap can never silently mint value — failures
//! surface as deterministic [`Error`] codes.
//!
//! ## Asset identity
//!
//! Every asset is identified by its Stellar Asset Contract [`Address`]. Native
//! XLM is just a wrapped SAC, so one map covers all tokens without a special
//! case. Storage keys stay consistent by always keying on `Address`.
//!
//! ## Storage model
//!
//! Helpers operate on Soroban SDK collections ([`Map<Address,i128>`] and
//! [`Vec<AssetAmount>`] / [`Vec<BalanceEntry>`]) so callers can keep the same
//! in-memory representation and only persist when ready. Pure arithmetic never
//! touches the ledger; storage-backed wrappers in consuming contracts add the
//! single persistent read/write around these helpers.
//!
//! ## Invariants
//!
//! - Balances are always `>= 0`; a missing entry reads as `0`.
//! - `0` is a valid balance and a valid query result — only *transfer* amounts
//!   are required to be `> 0` at the call site. Internal credit/debit helpers
//!   accept `0` as a no-op so reconciliation does not need a special case.
//! - Every `+`/`-` is checked: [`Error::Overflow`] on wrap, [`Error::InsufficientFunds`]
//!   when a debit would underflow, [`Error::InvalidAmount`] on negative inputs.
//! - Duplicate asset entries in an input vector are deduplicated by summing
//!   with checked math; a strict variant rejects duplicates with
//!   [`Error::InvalidInput`] when the caller needs to fail-closed on
//!   malformed input.

use soroban_sdk::{contracttype, Address, Env, Map, Vec};

use crate::errors::Error;
use crate::math::{checked_balance_add, checked_balance_sub};
use crate::types::AssetAmount;

/// A single asset balance entry for host-side or event payload use.
///
/// Identical in shape to [`AssetAmount`] but named for bookkeeping contexts.
/// Stored as a `#[contracttype]` so it can be emitted or persisted directly.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BalanceEntry {
    pub asset: Address,
    pub amount: i128,
}

/// Upper bound on distinct assets a single map may hold. Mirrors the treasury
/// cap (`MAX_TREASURY_ASSETS = 32`) so a map never grows unbounded inside one
/// invocation.
pub const MAX_BALANCE_ENTRIES: u32 = 32;

// ---------------------------------------------------------------------------
// Map queries — missing reads as zero
// ---------------------------------------------------------------------------

/// Create an empty `Map<Address,i128>`.
pub fn new_map(env: &Env) -> Map<Address, i128> {
    Map::new(env)
}

/// Read `asset` from `map`. A missing entry reads as `0` (zero balance).
pub fn get_balance(map: &Map<Address, i128>, asset: &Address) -> i128 {
    map.get(asset.clone()).unwrap_or(0)
}

/// Alias for [`get_balance`] — same semantics, alternative name for call sites
/// that prefer `balance_of`.
pub fn balance_of(map: &Map<Address, i128>, asset: &Address) -> i128 {
    get_balance(map, asset)
}

/// Alias for [`get_balance`] — query-style name.
pub fn query_balance(map: &Map<Address, i128>, asset: &Address) -> i128 {
    get_balance(map, asset)
}

/// Whether `map` contains a non-zero entry for `asset`.
pub fn contains_asset(map: &Map<Address, i128>, asset: &Address) -> bool {
    map.contains_key(asset.clone())
}

/// Whether `map` has no entries.
pub fn is_empty(map: &Map<Address, i128>) -> bool {
    map.is_empty()
}

/// Number of distinct assets in `map`.
pub fn len(map: &Map<Address, i128>) -> u32 {
    map.len()
}

/// Whether `asset` has a zero balance (missing or explicitly `0`).
pub fn is_zero_balance(map: &Map<Address, i128>, asset: &Address) -> bool {
    get_balance(map, asset) == 0
}

// ---------------------------------------------------------------------------
// Checked arithmetic on a Map
// ---------------------------------------------------------------------------

/// Credit `amount` to `asset` with overflow-safe math.
///
/// - `amount < 0` → [`Error::InvalidAmount`]
/// - `amount == 0` → no-op, returns current balance
/// - overflow → [`Error::Overflow`]
/// - otherwise sets `asset -> current + amount` and returns the new balance.
pub fn checked_add_balance(
    _env: &Env,
    map: &mut Map<Address, i128>,
    asset: Address,
    amount: i128,
) -> Result<i128, Error> {
    if amount < 0 {
        return Err(Error::InvalidAmount);
    }
    if amount == 0 {
        return Ok(get_balance(map, &asset));
    }
    if map.len() >= MAX_BALANCE_ENTRIES && !contains_asset(map, &asset) {
        return Err(Error::InvalidInput);
    }
    let cur = get_balance(map, &asset);
    let nxt = checked_balance_add(cur, amount)?;
    map.set(asset, nxt);
    Ok(nxt)
}

/// Debit `amount` from `asset` with underflow-safe math.
///
/// - `amount < 0` → [`Error::InvalidAmount`]
/// - `amount == 0` → no-op, returns current balance
/// - `balance < amount` → [`Error::InsufficientFunds`]
/// - otherwise sets `asset -> current - amount` (removing the entry when the
///   result is `0` to keep the map compact) and returns the new balance.
pub fn checked_sub_balance(
    _env: &Env,
    map: &mut Map<Address, i128>,
    asset: Address,
    amount: i128,
) -> Result<i128, Error> {
    if amount < 0 {
        return Err(Error::InvalidAmount);
    }
    if amount == 0 {
        return Ok(get_balance(map, &asset));
    }
    let cur = get_balance(map, &asset);
    let nxt = checked_balance_sub(cur, amount)?;
    if nxt == 0 {
        map.remove(asset);
    } else {
        map.set(asset, nxt);
    }
    Ok(nxt)
}

/// Alias for [`checked_add_balance`] — `credit` naming used by wallet/treasury.
pub fn credit(
    env: &Env,
    map: &mut Map<Address, i128>,
    asset: Address,
    amount: i128,
) -> Result<i128, Error> {
    checked_add_balance(env, map, asset, amount)
}

/// Alias for [`checked_sub_balance`] — `debit` naming.
pub fn debit(
    env: &Env,
    map: &mut Map<Address, i128>,
    asset: Address,
    amount: i128,
) -> Result<i128, Error> {
    checked_sub_balance(env, map, asset, amount)
}

/// Alias — `add_balance` naming some call sites expect.
pub fn add_balance(
    env: &Env,
    map: &mut Map<Address, i128>,
    asset: Address,
    amount: i128,
) -> Result<i128, Error> {
    checked_add_balance(env, map, asset, amount)
}

/// Alias — `sub_balance` naming.
pub fn sub_balance(
    env: &Env,
    map: &mut Map<Address, i128>,
    asset: Address,
    amount: i128,
) -> Result<i128, Error> {
    checked_sub_balance(env, map, asset, amount)
}

/// Set `asset` to exactly `amount` (must be `>= 0`). Used when restoring a
/// reconciled balance. A `0` removes the entry.
pub fn set_balance(
    map: &mut Map<Address, i128>,
    asset: Address,
    amount: i128,
) -> Result<i128, Error> {
    if amount < 0 {
        return Err(Error::InvalidAmount);
    }
    if amount == 0 {
        map.remove(asset);
    } else {
        if map.len() >= MAX_BALANCE_ENTRIES && !map.contains_key(asset.clone()) {
            return Err(Error::InvalidInput);
        }
        map.set(asset.clone(), amount);
    }
    Ok(amount)
}

// ---------------------------------------------------------------------------
// Vec <-> Map conversion + deduplication
// ---------------------------------------------------------------------------

/// Aggregate a `Vec<AssetAmount>` into a per-asset map, deduplicating by
/// summing duplicate assets with checked math. Each entry must be `> 0`
/// ([`Error::InvalidAmount`]), and any per-asset sum that overflows returns
/// [`Error::Overflow`]. An empty input is rejected with [`Error::InvalidInput`]
/// so callers can distinguish "nothing to do" from "zero-valued transfer".
pub fn aggregate_asset_amounts(
    env: &Env,
    amounts: &Vec<AssetAmount>,
) -> Result<Map<Address, i128>, Error> {
    if amounts.is_empty() {
        return Err(Error::InvalidInput);
    }
    let mut totals: Map<Address, i128> = Map::new(env);
    for entry in amounts.iter() {
        if entry.amount <= 0 {
            return Err(Error::InvalidAmount);
        }
        let cur = totals.get(entry.asset.clone()).unwrap_or(0);
        let nxt = checked_balance_add(cur, entry.amount)?;
        if totals.len() >= MAX_BALANCE_ENTRIES && !totals.contains_key(entry.asset.clone()) {
            return Err(Error::InvalidInput);
        }
        totals.set(entry.asset.clone(), nxt);
    }
    Ok(totals)
}

/// Lenient Vec<AssetAmount> deduplication: identical to [`aggregate_asset_amounts`]
/// but exposed under a `dedup_*` name for call sites that think in terms of
/// deduplication. Duplicate assets are merged with checked addition.
pub fn dedup_asset_amounts(
    env: &Env,
    amounts: &Vec<AssetAmount>,
) -> Result<Map<Address, i128>, Error> {
    aggregate_asset_amounts(env, amounts)
}

/// Strict deduplication: reject any `Vec<AssetAmount>` that contains the same
/// `asset` more than once ([`Error::InvalidInput`]), otherwise return the map.
/// Use when the caller must fail-closed on malformed input rather than merging.
pub fn require_unique_assets(amounts: &Vec<AssetAmount>) -> Result<(), Error> {
    for i in 0..amounts.len() {
        let a = amounts.get_unchecked(i).asset.clone();
        for j in (i + 1)..amounts.len() {
            if amounts.get_unchecked(j).asset == a {
                return Err(Error::InvalidInput);
            }
        }
    }
    Ok(())
}

/// Aggregate a `Vec<BalanceEntry>` leniently (duplicate assets summed). Entries
/// must be `>= 0` (zero allowed, negative rejected). Overflow is
/// [`Error::Overflow`].
pub fn aggregate_entries(
    env: &Env,
    entries: &Vec<BalanceEntry>,
) -> Result<Map<Address, i128>, Error> {
    let mut totals: Map<Address, i128> = Map::new(env);
    for e in entries.iter() {
        if e.amount < 0 {
            return Err(Error::InvalidAmount);
        }
        if e.amount == 0 {
            continue;
        }
        let cur = totals.get(e.asset.clone()).unwrap_or(0);
        let nxt = checked_balance_add(cur, e.amount)?;
        if totals.len() >= MAX_BALANCE_ENTRIES && !totals.contains_key(e.asset.clone()) {
            return Err(Error::InvalidInput);
        }
        totals.set(e.asset.clone(), nxt);
    }
    Ok(totals)
}

/// Lenient deduplication for `Vec<BalanceEntry>` — merges duplicates.
pub fn dedup_balances(env: &Env, entries: &Vec<BalanceEntry>) -> Result<Map<Address, i128>, Error> {
    aggregate_entries(env, entries)
}

/// Build a map from `Vec<BalanceEntry>` with strict uniqueness. Duplicate asset
/// → [`Error::InvalidInput`]. Negative amount → [`Error::InvalidAmount`].
pub fn from_entries_strict(
    env: &Env,
    entries: Vec<BalanceEntry>,
) -> Result<Map<Address, i128>, Error> {
    let mut map: Map<Address, i128> = Map::new(env);
    for e in entries.iter() {
        if e.amount < 0 {
            return Err(Error::InvalidAmount);
        }
        if map.contains_key(e.asset.clone()) {
            return Err(Error::InvalidInput);
        }
        if e.amount == 0 {
            continue;
        }
        if map.len() >= MAX_BALANCE_ENTRIES {
            return Err(Error::InvalidInput);
        }
        map.set(e.asset.clone(), e.amount);
    }
    Ok(map)
}

/// Convert a map back to a `Vec<BalanceEntry>` preserving no particular order
/// (iteration order of `Map`).
pub fn to_entries(env: &Env, map: &Map<Address, i128>) -> Vec<BalanceEntry> {
    let mut out = Vec::new(env);
    for (asset, amount) in map.iter() {
        out.push_back(BalanceEntry { asset, amount });
    }
    out
}

/// Convert a map to `Vec<AssetAmount>` (treasury/escrow shaped).
pub fn to_asset_amounts(env: &Env, map: &Map<Address, i128>) -> Vec<AssetAmount> {
    let mut out = Vec::new(env);
    for (asset, amount) in map.iter() {
        out.push_back(AssetAmount { asset, amount });
    }
    out
}

// ---------------------------------------------------------------------------
// Map-to-map helpers + reconciliation
// ---------------------------------------------------------------------------

/// Merge `src` into `dst` with checked per-asset addition. Duplicate assets
/// have their amounts summed; overflow → [`Error::Overflow`].
pub fn merge_maps(dst: &mut Map<Address, i128>, src: &Map<Address, i128>) -> Result<(), Error> {
    for (asset, amount) in src.iter() {
        let cur = dst.get(asset.clone()).unwrap_or(0);
        let nxt = checked_balance_add(cur, amount)?;
        if dst.len() >= MAX_BALANCE_ENTRIES && !dst.contains_key(asset.clone()) {
            return Err(Error::InvalidInput);
        }
        dst.set(asset, nxt);
    }
    Ok(())
}

/// Subtract `src` from `dst` per asset with underflow checks. Any asset where
/// `dst < src` → [`Error::InsufficientFunds`]. Result zero entries are removed.
pub fn subtract_maps(dst: &mut Map<Address, i128>, src: &Map<Address, i128>) -> Result<(), Error> {
    for (asset, amount) in src.iter() {
        let cur = dst.get(asset.clone()).unwrap_or(0);
        let nxt = checked_balance_sub(cur, amount)?;
        if nxt == 0 {
            dst.remove(asset);
        } else {
            dst.set(asset, nxt);
        }
    }
    Ok(())
}

/// Ensure every asset in `required` has at least that amount in `available`.
/// Returns [`Error::InsufficientFunds`] on the first shortfall.
pub fn ensure_sufficient(
    available: &Map<Address, i128>,
    required: &Map<Address, i128>,
) -> Result<(), Error> {
    for (asset, amount) in required.iter() {
        let have = available.get(asset.clone()).unwrap_or(0);
        if have < amount {
            return Err(Error::InsufficientFunds);
        }
    }
    Ok(())
}

/// Ledger delta for one asset: `external - internal` with checked math.
/// Both inputs must be `>= 0` ([`Error::InvalidAmount`]), result may be
/// negative (external below internal) and the subtraction is still checked so
/// `i128::MIN` edge cases surface as [`Error::Overflow`].
pub fn ledger_delta(internal: i128, external: i128) -> Result<i128, Error> {
    if internal < 0 || external < 0 {
        return Err(Error::InvalidAmount);
    }
    external.checked_sub(internal).ok_or(Error::Overflow)
}

/// Verify a single asset reconciles: the on-chain token balance equals the
/// internal bookkeeping balance. Mismatch → [`Error::InvalidState`].
pub fn verify_single_reconciliation(internal: i128, external: i128) -> Result<(), Error> {
    if internal < 0 || external < 0 {
        return Err(Error::InvalidAmount);
    }
    if internal != external {
        return Err(Error::InvalidState);
    }
    Ok(())
}

/// Reconcile two maps asset-by-asset. Every asset that appears in either map
/// must have equal balances or the call fails with [`Error::InvalidState`]
/// on the first mismatch. Missing assets are treated as `0`, so a map that
/// has an asset the other lacks is a mismatch unless that balance is `0`.
pub fn reconcile_maps(a: &Map<Address, i128>, b: &Map<Address, i128>) -> Result<(), Error> {
    // Check every asset in a.
    for (asset, amount) in a.iter() {
        let other = b.get(asset.clone()).unwrap_or(0);
        if amount != other {
            return Err(Error::InvalidState);
        }
    }
    // Assets only in b.
    for (asset, amount) in b.iter() {
        if !a.contains_key(asset.clone()) && amount != 0 {
            return Err(Error::InvalidState);
        }
    }
    Ok(())
}

/// Per-asset deltas `external - internal` for every asset in either map. Zero
/// deltas are omitted to keep the result compact.
pub fn deltas(
    env: &Env,
    internal: &Map<Address, i128>,
    external: &Map<Address, i128>,
) -> Result<Map<Address, i128>, Error> {
    let mut out: Map<Address, i128> = Map::new(env);
    // Union of keys: iterate both maps, compute delta once per asset.
    for (asset, ext) in external.iter() {
        let int = internal.get(asset.clone()).unwrap_or(0);
        let d = ledger_delta(int, ext)?;
        if d != 0 {
            out.set(asset, d);
        }
    }
    for (asset, int) in internal.iter() {
        if external.contains_key(asset.clone()) {
            continue;
        }
        let d = ledger_delta(int, 0)?;
        if d != 0 {
            out.set(asset, d);
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Checked arithmetic free helpers (non-map) for call sites that already hold
// a plain i128 balance.
// ---------------------------------------------------------------------------

/// Checked addition for a single balance (non-negative operands).
pub fn checked_add(a: i128, b: i128) -> Result<i128, Error> {
    checked_balance_add(a, b)
}

/// Checked subtraction for a single balance (debit semantics).
pub fn checked_sub(balance: i128, amount: i128) -> Result<i128, Error> {
    checked_balance_sub(balance, amount)
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::Env;

    fn addr(env: &Env) -> Address {
        Address::generate(env)
    }

    #[test]
    fn new_map_is_empty_and_query_is_zero() {
        let env = Env::default();
        let m = new_map(&env);
        let a = addr(&env);
        assert!(is_empty(&m));
        assert_eq!(len(&m), 0);
        assert_eq!(get_balance(&m, &a), 0);
        assert_eq!(balance_of(&m, &a), 0);
        assert_eq!(query_balance(&m, &a), 0);
        assert!(is_zero_balance(&m, &a));
        assert!(!contains_asset(&m, &a));
    }

    #[test]
    fn checked_add_happy_path_and_zero_noop() {
        let env = Env::default();
        let mut m = new_map(&env);
        let a = addr(&env);
        assert_eq!(checked_add_balance(&env, &mut m, a.clone(), 0), Ok(0));
        assert_eq!(len(&m), 0);
        assert_eq!(checked_add_balance(&env, &mut m, a.clone(), 10), Ok(10));
        assert_eq!(get_balance(&m, &a), 10);
        assert_eq!(checked_add_balance(&env, &mut m, a.clone(), 5), Ok(15));
        assert_eq!(get_balance(&m, &a), 15);
        // aliases agree
        assert_eq!(add_balance(&env, &mut m, a.clone(), 5), Ok(20));
        assert_eq!(credit(&env, &mut m, a.clone(), 0), Ok(20));
    }

    #[test]
    fn checked_add_negative_rejected() {
        let env = Env::default();
        let mut m = new_map(&env);
        let a = addr(&env);
        assert_eq!(
            checked_add_balance(&env, &mut m, a.clone(), -1),
            Err(Error::InvalidAmount)
        );
        assert_eq!(get_balance(&m, &a), 0);
        assert_eq!(
            add_balance(&env, &mut m, a.clone(), -100),
            Err(Error::InvalidAmount)
        );
    }

    #[test]
    fn checked_add_overflow_at_max() {
        let env = Env::default();
        let mut m = new_map(&env);
        let a = addr(&env);
        assert_eq!(
            checked_add_balance(&env, &mut m, a.clone(), i128::MAX),
            Ok(i128::MAX)
        );
        assert_eq!(get_balance(&m, &a), i128::MAX);
        assert_eq!(
            checked_add_balance(&env, &mut m, a.clone(), 1),
            Err(Error::Overflow)
        );
        // still MAX, not wrapped
        assert_eq!(get_balance(&m, &a), i128::MAX);
        // adding to MAX via merge also overflows
        let mut m2 = new_map(&env);
        m2.set(a.clone(), 1);
        assert_eq!(merge_maps(&mut m, &m2), Err(Error::Overflow));
    }

    #[test]
    fn checked_sub_happy_path_and_removes_on_zero() {
        let env = Env::default();
        let mut m = new_map(&env);
        let a = addr(&env);
        checked_add_balance(&env, &mut m, a.clone(), 100).unwrap();
        assert_eq!(checked_sub_balance(&env, &mut m, a.clone(), 30), Ok(70));
        assert_eq!(get_balance(&m, &a), 70);
        // zero sub is no-op
        assert_eq!(checked_sub_balance(&env, &mut m, a.clone(), 0), Ok(70));
        assert_eq!(get_balance(&m, &a), 70);
        // debit alias
        assert_eq!(debit(&env, &mut m, a.clone(), 20), Ok(50));
        // sub_balance alias draining to zero removes the entry
        assert_eq!(sub_balance(&env, &mut m, a.clone(), 50), Ok(0));
        assert_eq!(get_balance(&m, &a), 0);
        assert!(!contains_asset(&m, &a));
        assert!(is_empty(&m));
    }

    #[test]
    fn checked_sub_rejects_negative_and_insufficient() {
        let env = Env::default();
        let mut m = new_map(&env);
        let a = addr(&env);
        checked_add_balance(&env, &mut m, a.clone(), 10).unwrap();
        assert_eq!(
            checked_sub_balance(&env, &mut m, a.clone(), -1),
            Err(Error::InvalidAmount)
        );
        assert_eq!(
            checked_sub_balance(&env, &mut m, a.clone(), 11),
            Err(Error::InsufficientFunds)
        );
        assert_eq!(get_balance(&m, &a), 10);
        // sub from missing is insufficient
        let b = addr(&env);
        assert_eq!(
            checked_sub_balance(&env, &mut m, b.clone(), 1),
            Err(Error::InsufficientFunds)
        );
    }

    #[test]
    fn checked_sub_at_zero_balance_insufficient() {
        let env = Env::default();
        let mut m = new_map(&env);
        let a = addr(&env);
        assert_eq!(get_balance(&m, &a), 0);
        assert_eq!(
            checked_sub_balance(&env, &mut m, a.clone(), 1),
            Err(Error::InsufficientFunds)
        );
    }

    #[test]
    fn set_balance_happy_and_zero_removes() {
        let env = Env::default();
        let mut m = new_map(&env);
        let a = addr(&env);
        assert_eq!(set_balance(&mut m, a.clone(), 42), Ok(42));
        assert_eq!(get_balance(&m, &a), 42);
        assert_eq!(set_balance(&mut m, a.clone(), 0), Ok(0));
        assert!(!contains_asset(&m, &a));
        assert_eq!(
            set_balance(&mut m, a.clone(), -1),
            Err(Error::InvalidAmount)
        );
    }

    #[test]
    fn multi_currency_independent() {
        let env = Env::default();
        let mut m = new_map(&env);
        let a = addr(&env);
        let b = addr(&env);
        let c = addr(&env);
        checked_add_balance(&env, &mut m, a.clone(), 100).unwrap();
        checked_add_balance(&env, &mut m, b.clone(), 200).unwrap();
        checked_add_balance(&env, &mut m, c.clone(), 300).unwrap();
        assert_eq!(get_balance(&m, &a), 100);
        assert_eq!(get_balance(&m, &b), 200);
        assert_eq!(get_balance(&m, &c), 300);
        assert_eq!(len(&m), 3);
        // draining one does not affect others
        checked_sub_balance(&env, &mut m, b.clone(), 200).unwrap();
        assert_eq!(get_balance(&m, &a), 100);
        assert_eq!(get_balance(&m, &b), 0);
        assert_eq!(get_balance(&m, &c), 300);
        assert_eq!(len(&m), 2);
    }

    #[test]
    fn aggregate_asset_amounts_dedup_with_checked_math() {
        let env = Env::default();
        let a = addr(&env);
        let b = addr(&env);
        let mut v = Vec::new(&env);
        v.push_back(AssetAmount {
            asset: a.clone(),
            amount: 10,
        });
        v.push_back(AssetAmount {
            asset: b.clone(),
            amount: 20,
        });
        v.push_back(AssetAmount {
            asset: a.clone(),
            amount: 5,
        });
        let m = aggregate_asset_amounts(&env, &v).unwrap();
        assert_eq!(get_balance(&m, &a), 15);
        assert_eq!(get_balance(&m, &b), 20);
        assert_eq!(len(&m), 2);
        // dedup alias agrees
        let m2 = dedup_asset_amounts(&env, &v).unwrap();
        assert_eq!(m, m2);
    }

    #[test]
    fn aggregate_rejects_empty_negative_and_zero_amounts() {
        let env = Env::default();
        let a = addr(&env);
        let empty: Vec<AssetAmount> = Vec::new(&env);
        assert_eq!(
            aggregate_asset_amounts(&env, &empty),
            Err(Error::InvalidInput)
        );
        let mut v = Vec::new(&env);
        v.push_back(AssetAmount {
            asset: a.clone(),
            amount: 0,
        });
        assert_eq!(aggregate_asset_amounts(&env, &v), Err(Error::InvalidAmount));
        let mut v2 = Vec::new(&env);
        v2.push_back(AssetAmount {
            asset: a.clone(),
            amount: -5,
        });
        assert_eq!(
            aggregate_asset_amounts(&env, &v2),
            Err(Error::InvalidAmount)
        );
    }

    #[test]
    fn aggregate_overflow_on_duplicate_sum() {
        let env = Env::default();
        let a = addr(&env);
        let mut v = Vec::new(&env);
        v.push_back(AssetAmount {
            asset: a.clone(),
            amount: i128::MAX,
        });
        v.push_back(AssetAmount {
            asset: a.clone(),
            amount: 1,
        });
        assert_eq!(aggregate_asset_amounts(&env, &v), Err(Error::Overflow));
    }

    #[test]
    fn strict_uniqueness_rejects_duplicate() {
        let env = Env::default();
        let a = addr(&env);
        let b = addr(&env);
        let mut v = Vec::new(&env);
        v.push_back(AssetAmount {
            asset: a.clone(),
            amount: 10,
        });
        v.push_back(AssetAmount {
            asset: b.clone(),
            amount: 20,
        });
        assert_eq!(require_unique_assets(&v), Ok(()));
        v.push_back(AssetAmount {
            asset: a.clone(),
            amount: 5,
        });
        assert_eq!(require_unique_assets(&v), Err(Error::InvalidInput));
    }

    #[test]
    fn aggregate_entries_zero_skipped_and_negative_rejected() {
        let env = Env::default();
        let a = addr(&env);
        let b = addr(&env);
        let mut v = Vec::new(&env);
        v.push_back(BalanceEntry {
            asset: a.clone(),
            amount: 10,
        });
        v.push_back(BalanceEntry {
            asset: b.clone(),
            amount: 0,
        });
        v.push_back(BalanceEntry {
            asset: a.clone(),
            amount: 5,
        });
        let m = aggregate_entries(&env, &v).unwrap();
        assert_eq!(get_balance(&m, &a), 15);
        assert!(!contains_asset(&m, &b));
        // negative rejected
        let mut v2 = Vec::new(&env);
        v2.push_back(BalanceEntry {
            asset: a.clone(),
            amount: -1,
        });
        assert_eq!(aggregate_entries(&env, &v2), Err(Error::InvalidAmount));
    }

    #[test]
    fn from_entries_strict_rejects_duplicate_and_negative() {
        let env = Env::default();
        let a = addr(&env);
        let mut v = Vec::new(&env);
        v.push_back(BalanceEntry {
            asset: a.clone(),
            amount: 10,
        });
        v.push_back(BalanceEntry {
            asset: a.clone(),
            amount: 20,
        });
        assert_eq!(from_entries_strict(&env, v), Err(Error::InvalidInput));
        let mut v2 = Vec::new(&env);
        v2.push_back(BalanceEntry {
            asset: a.clone(),
            amount: -1,
        });
        assert_eq!(from_entries_strict(&env, v2), Err(Error::InvalidAmount));
        // zero entry is skipped
        let mut v3 = Vec::new(&env);
        v3.push_back(BalanceEntry {
            asset: a.clone(),
            amount: 0,
        });
        let m = from_entries_strict(&env, v3).unwrap();
        assert!(is_empty(&m));
    }

    #[test]
    fn to_entries_roundtrip() {
        let env = Env::default();
        let mut m = new_map(&env);
        let a = addr(&env);
        let b = addr(&env);
        checked_add_balance(&env, &mut m, a.clone(), 11).unwrap();
        checked_add_balance(&env, &mut m, b.clone(), 22).unwrap();
        let entries = to_entries(&env, &m);
        assert_eq!(entries.len(), 2);
        let m2 = aggregate_entries(&env, &entries).unwrap();
        assert_eq!(m, m2);
        let amounts = to_asset_amounts(&env, &m);
        assert_eq!(amounts.len(), 2);
    }

    #[test]
    fn merge_and_subtract_maps() {
        let env = Env::default();
        let mut a = new_map(&env);
        let mut b = new_map(&env);
        let x = addr(&env);
        let y = addr(&env);
        checked_add_balance(&env, &mut a, x.clone(), 100).unwrap();
        checked_add_balance(&env, &mut a, y.clone(), 50).unwrap();
        checked_add_balance(&env, &mut b, x.clone(), 20).unwrap();
        checked_add_balance(&env, &mut b, y.clone(), 10).unwrap();
        merge_maps(&mut a, &b).unwrap();
        assert_eq!(get_balance(&a, &x), 120);
        assert_eq!(get_balance(&a, &y), 60);
        // subtract back
        subtract_maps(&mut a, &b).unwrap();
        assert_eq!(get_balance(&a, &x), 100);
        assert_eq!(get_balance(&a, &y), 50);
        // over-subtract insufficient
        let mut c = new_map(&env);
        checked_add_balance(&env, &mut c, x.clone(), 200).unwrap();
        assert_eq!(subtract_maps(&mut a, &c), Err(Error::InsufficientFunds));
    }

    #[test]
    fn ensure_sufficient_checks_all_assets() {
        let env = Env::default();
        let mut have = new_map(&env);
        let mut need = new_map(&env);
        let a = addr(&env);
        let b = addr(&env);
        checked_add_balance(&env, &mut have, a.clone(), 100).unwrap();
        checked_add_balance(&env, &mut need, a.clone(), 100).unwrap();
        assert_eq!(ensure_sufficient(&have, &need), Ok(()));
        checked_add_balance(&env, &mut need, b.clone(), 1).unwrap();
        assert_eq!(
            ensure_sufficient(&have, &need),
            Err(Error::InsufficientFunds)
        );
    }

    #[test]
    fn ledger_delta_and_verification() {
        assert_eq!(ledger_delta(100, 150), Ok(50));
        assert_eq!(ledger_delta(100, 100), Ok(0));
        assert_eq!(ledger_delta(150, 100), Ok(-50));
        assert_eq!(ledger_delta(-1, 0), Err(Error::InvalidAmount));
        assert_eq!(ledger_delta(0, -1), Err(Error::InvalidAmount));
        assert_eq!(ledger_delta(i128::MAX, 0), Ok(-i128::MAX));
        // verify
        assert_eq!(verify_single_reconciliation(100, 100), Ok(()));
        assert_eq!(
            verify_single_reconciliation(100, 101),
            Err(Error::InvalidState)
        );
        assert_eq!(
            verify_single_reconciliation(-1, 0),
            Err(Error::InvalidAmount)
        );
    }

    #[test]
    fn reconcile_maps_and_deltas() {
        let env = Env::default();
        let mut a = new_map(&env);
        let mut b = new_map(&env);
        let x = addr(&env);
        let y = addr(&env);
        checked_add_balance(&env, &mut a, x.clone(), 100).unwrap();
        checked_add_balance(&env, &mut a, y.clone(), 50).unwrap();
        checked_add_balance(&env, &mut b, x.clone(), 100).unwrap();
        checked_add_balance(&env, &mut b, y.clone(), 50).unwrap();
        assert_eq!(reconcile_maps(&a, &b), Ok(()));
        checked_add_balance(&env, &mut b, x.clone(), 1).unwrap();
        assert_eq!(reconcile_maps(&a, &b), Err(Error::InvalidState));
        // deltas
        let d = deltas(&env, &a, &b).unwrap();
        assert_eq!(get_balance(&d, &x), 1);
        assert_eq!(get_balance(&d, &y), 0);
        assert!(!contains_asset(&d, &y));
    }

    #[test]
    fn reconcile_missing_is_mismatch_unless_zero() {
        let env = Env::default();
        let mut a = new_map(&env);
        let mut b = new_map(&env);
        let x = addr(&env);
        checked_add_balance(&env, &mut a, x.clone(), 10).unwrap();
        // b missing x (treated as 0) -> mismatch
        assert_eq!(reconcile_maps(&a, &b), Err(Error::InvalidState));
        assert_eq!(reconcile_maps(&b, &a), Err(Error::InvalidState));
        // both empty reconciles
        let empty = new_map(&env);
        assert_eq!(reconcile_maps(&empty, &empty), Ok(()));
    }

    #[test]
    fn checked_math_free_fns_handle_max() {
        assert_eq!(checked_add(i128::MAX, 0), Ok(i128::MAX));
        assert_eq!(checked_add(i128::MAX, 1), Err(Error::Overflow));
        assert_eq!(checked_add(0, i128::MAX), Ok(i128::MAX));
        assert_eq!(checked_sub(i128::MAX, i128::MAX), Ok(0));
        assert_eq!(checked_sub(0, 1), Err(Error::InsufficientFunds));
        assert_eq!(checked_sub(-1, 1), Err(Error::InvalidAmount));
        assert_eq!(checked_sub(10, -1), Err(Error::InvalidAmount));
    }

    #[test]
    fn dedup_balances_merges_and_overflows() {
        let env = Env::default();
        let a = addr(&env);
        let mut v = Vec::new(&env);
        v.push_back(BalanceEntry {
            asset: a.clone(),
            amount: i128::MAX,
        });
        v.push_back(BalanceEntry {
            asset: a.clone(),
            amount: 1,
        });
        assert_eq!(dedup_balances(&env, &v), Err(Error::Overflow));
        // happy dedup
        let mut v2 = Vec::new(&env);
        v2.push_back(BalanceEntry {
            asset: a.clone(),
            amount: 40,
        });
        v2.push_back(BalanceEntry {
            asset: a.clone(),
            amount: 2,
        });
        let m = dedup_balances(&env, &v2).unwrap();
        assert_eq!(get_balance(&m, &a), 42);
    }

    #[test]
    fn zero_balance_stays_zero_after_roundtrip() {
        let env = Env::default();
        let a = addr(&env);
        let mut m = new_map(&env);
        // never touched
        assert_eq!(get_balance(&m, &a), 0);
        // credit zero
        assert_eq!(checked_add_balance(&env, &mut m, a.clone(), 0), Ok(0));
        assert_eq!(get_balance(&m, &a), 0);
        // debit zero
        assert_eq!(checked_sub_balance(&env, &mut m, a.clone(), 0), Ok(0));
        assert_eq!(get_balance(&m, &a), 0);
        // entry not created for zero
        assert!(!contains_asset(&m, &a));
    }

    #[test]
    fn max_entries_guard() {
        let env = Env::default();
        let mut m = new_map(&env);
        for _ in 0..MAX_BALANCE_ENTRIES {
            let a = addr(&env);
            checked_add_balance(&env, &mut m, a, 1).unwrap();
        }
        assert_eq!(len(&m), MAX_BALANCE_ENTRIES);
        let extra = addr(&env);
        assert_eq!(
            checked_add_balance(&env, &mut m, extra.clone(), 1),
            Err(Error::InvalidInput)
        );
        // adding to existing still ok
        let existing = m.iter().next().unwrap().0;
        assert!(checked_add_balance(&env, &mut m, existing.clone(), 1).is_ok());
    }
}
