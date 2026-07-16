// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stellar TimeLock contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

#![no_std]
//! XLM Vault — non-custodial time-lock for the Stellar Soroban runtime.
//!
//! This contract is the **enforcement layer** for the XLM Vault mobile app.
//! The mobile app's `FastAPI + MongoDB` backend is a thin persistence layer
//! that mirrors the rules in this file 1:1; on mainnet/testnet this contract
//! is the source of truth.
//!
//! Guarantees:
//! - Only the vault owner may `deposit`, `extend_lock`, or `withdraw`.
//! - Withdrawals are blocked by `env.ledger().timestamp()` before unlock.
//! - Lock extensions ONLY — `extend_lock` rejects any reduction.
//! - No admin role, no privileged accounts, no emergency-unlock function.
//! - No backdoor: there is no `set_owner`, no `pause`, no `upgrade` path.
//!
//! Built against `soroban-sdk = "21"`. Build with `cargo build --release --target wasm32-unknown-unknown`.

use soroban_sdk::{
    contract, contractimpl, contracterror, contracttype,
    Address, Env, String, Symbol, Vec,
};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NotOwner = 1,
    StillLocked = 2,
    AlreadyWithdrawn = 3,
    ShortenForbidden = 4,
    VaultNotFound = 5,
    InvalidAmount = 6,
    InvalidTimestamp = 7,
    AlreadyInitialised = 8,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct Vault {
    pub vault_id: u64,
    pub owner: Address,
    pub name: String,
    pub balance: i128,
    pub unlock_timestamp: u64,
    pub created_timestamp: u64,
    pub withdrawn: bool,
}

#[contracttype]
pub enum DataKey {
    /// XLM (or other native asset) token contract address used by all vaults.
    /// Set once via `init`; the contract intentionally exposes no setter.
    Token,
    /// Monotonic counter for vault ids.
    NextId,
    /// Vault by id.
    Vault(u64),
    /// Per-owner index of vault ids.
    Owned(Address),
}

#[contract]
pub struct XlmVault;

#[contractimpl]
impl XlmVault {
    /// One-time initializer wiring the native XLM token contract address.
    /// After init, the token reference is immutable — there is no setter.
    pub fn init(env: Env, token: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Token) {
            return Err(Error::AlreadyInitialised);
        }
        env.storage().instance().set(&DataKey::Token, &token);
        env.storage().instance().set(&DataKey::NextId, &0u64);
        Ok(())
    }

    /// Create a vault and lock `initial_deposit` of the configured asset.
    /// `unlock_timestamp` is recorded immutably; it can only ever be PUSHED
    /// FORWARD via `extend_lock`.
    pub fn create_vault(
        env: Env,
        owner: Address,
        name: String,
        initial_deposit: i128,
        unlock_timestamp: u64,
    ) -> Result<u64, Error> {
        owner.require_auth();
        if initial_deposit <= 0 {
            return Err(Error::InvalidAmount);
        }
        let now = env.ledger().timestamp();
        if unlock_timestamp <= now {
            return Err(Error::InvalidTimestamp);
        }

        Self::pull(&env, &owner, initial_deposit);

        let id: u64 = env
            .storage()
            .instance()
            .get(&DataKey::NextId)
            .unwrap_or(0u64);
        let next = id.checked_add(1).ok_or(Error::InvalidAmount)?;
        env.storage().instance().set(&DataKey::NextId, &next);

        let v = Vault {
            vault_id: id,
            owner: owner.clone(),
            name,
            balance: initial_deposit,
            unlock_timestamp,
            created_timestamp: now,
            withdrawn: false,
        };
        env.storage().persistent().set(&DataKey::Vault(id), &v);

        let mut owned: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::Owned(owner.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        owned.push_back(id);
        env.storage()
            .persistent()
            .set(&DataKey::Owned(owner.clone()), &owned);

        env.events().publish(
            (Symbol::new(&env, "create"), owner),
            (id, initial_deposit, unlock_timestamp),
        );
        Ok(id)
    }

    /// Add more funds to an existing vault. **Does not** alter `unlock_timestamp`.
    pub fn deposit(env: Env, caller: Address, vault_id: u64, amount: i128) -> Result<(), Error> {
        caller.require_auth();
        if amount <= 0 {
            return Err(Error::InvalidAmount);
        }
        let mut v: Vault = Self::load(&env, vault_id)?;
        if v.owner != caller {
            return Err(Error::NotOwner);
        }
        if v.withdrawn {
            return Err(Error::AlreadyWithdrawn);
        }
        Self::pull(&env, &caller, amount);
        v.balance += amount;
        env.storage()
            .persistent()
            .set(&DataKey::Vault(vault_id), &v);
        env.events()
            .publish((Symbol::new(&env, "deposit"), caller), (vault_id, amount));
        Ok(())
    }

    /// Push the unlock timestamp further into the future by `additional_seconds`.
    /// Reducing or zeroing the lock is impossible — there is no `set_unlock` API.
    pub fn extend_lock(
        env: Env,
        caller: Address,
        vault_id: u64,
        additional_seconds: u64,
    ) -> Result<u64, Error> {
        caller.require_auth();
        if additional_seconds == 0 {
            return Err(Error::ShortenForbidden);
        }
        let mut v: Vault = Self::load(&env, vault_id)?;
        if v.owner != caller {
            return Err(Error::NotOwner);
        }
        if v.withdrawn {
            return Err(Error::AlreadyWithdrawn);
        }
        v.unlock_timestamp = v
            .unlock_timestamp
            .checked_add(additional_seconds)
            .ok_or(Error::InvalidTimestamp)?;
        env.storage()
            .persistent()
            .set(&DataKey::Vault(vault_id), &v);
        env.events().publish(
            (Symbol::new(&env, "extend"), caller),
            (vault_id, v.unlock_timestamp),
        );
        Ok(v.unlock_timestamp)
    }

    /// Withdraw the full vault balance to the owner address.
    /// Reverts with `StillLocked` if `env.ledger().timestamp() < unlock_timestamp`.
    pub fn withdraw(env: Env, caller: Address, vault_id: u64) -> Result<i128, Error> {
        caller.require_auth();
        let mut v: Vault = Self::load(&env, vault_id)?;
        if v.owner != caller {
            return Err(Error::NotOwner);
        }
        if v.withdrawn {
            return Err(Error::AlreadyWithdrawn);
        }
        if env.ledger().timestamp() < v.unlock_timestamp {
            return Err(Error::StillLocked);
        }
        let amount = v.balance;
        v.balance = 0;
        v.withdrawn = true;
        env.storage()
            .persistent()
            .set(&DataKey::Vault(vault_id), &v);
        Self::push(&env, &caller, amount);
        env.events()
            .publish((Symbol::new(&env, "withdraw"), caller), (vault_id, amount));
        Ok(amount)
    }

    /// Read-only — fetch a vault by id.
    pub fn get_vault(env: Env, vault_id: u64) -> Result<Vault, Error> {
        Self::load(&env, vault_id)
    }

    /// Read-only — list vault ids owned by `owner`.
    pub fn list_owned(env: Env, owner: Address) -> Vec<u64> {
        env.storage()
            .persistent()
            .get(&DataKey::Owned(owner))
            .unwrap_or_else(|| Vec::new(&env))
    }

    // ---------------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------------

    fn load(env: &Env, vault_id: u64) -> Result<Vault, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Vault(vault_id))
            .ok_or(Error::VaultNotFound)
    }

    fn token(env: &Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::Token)
            .expect("contract not initialised")
    }

    fn pull(env: &Env, from: &Address, amount: i128) {
        let token = Self::token(env);
        let client = soroban_sdk::token::TokenClient::new(env, &token);
        client.transfer(from, &env.current_contract_address(), &amount);
    }

    fn push(env: &Env, to: &Address, amount: i128) {
        let token = Self::token(env);
        let client = soroban_sdk::token::TokenClient::new(env, &token);
        client.transfer(&env.current_contract_address(), to, &amount);
    }
}

// ---------------------------------------------------------------------------
// Tests — invariants the mobile app and FastAPI mirror also enforce.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, Ledger, LedgerInfo},
        token::{StellarAssetClient, TokenClient},
        Env,
    };

    const DAY: u64 = 86_400;

    fn now(env: &Env) -> u64 {
        env.ledger().timestamp()
    }

    fn set_time(env: &Env, ts: u64) {
        env.ledger().set(LedgerInfo {
            timestamp: ts,
            protocol_version: 22,
            sequence_number: 10,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 16,
            min_persistent_entry_ttl: 100,
            max_entry_ttl: 1000,
        });
    }

    fn setup() -> (Env, XlmVaultClient<'static>, Address, TokenClient<'static>, StellarAssetClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        set_time(&env, 1_700_000_000);

        // Native-style Stellar asset issued by `admin`.
        let admin = Address::generate(&env);
        let sac = env.register_stellar_asset_contract_v2(admin.clone());
        let token = TokenClient::new(&env, &sac.address());
        let mint = StellarAssetClient::new(&env, &sac.address());

        // Vault contract.
        let vault_id = env.register_contract(None, XlmVault);
        let client = XlmVaultClient::new(&env, &vault_id);
        client.init(&sac.address());

        (env, client, admin, token, mint)
    }

    fn fund(env: &Env, mint: &StellarAssetClient, who: &Address, amount: i128) {
        mint.mint(who, &amount);
        // sanity
        assert!(amount > 0);
        let _ = env; // suppress unused warning on some toolchains
    }

    #[test]
    fn create_locks_funds_and_assigns_owner() {
        let (env, client, _admin, token, mint) = setup();
        let owner = Address::generate(&env);
        fund(&env, &mint, &owner, 10_000);

        let unlock = now(&env) + 30 * DAY;
        let id = client
            .create_vault(&owner, &String::from_str(&env, "Rent"), &1_500, &unlock)
            ;

        let v = client.get_vault(&id);
        assert_eq!(v.balance, 1_500);
        assert_eq!(v.owner, owner);
        assert_eq!(v.unlock_timestamp, unlock);
        assert!(!v.withdrawn);
        assert_eq!(token.balance(&owner), 8_500);
    }

    #[test]
    fn create_rejects_past_unlock() {
        let (env, client, _admin, _token, mint) = setup();
        let owner = Address::generate(&env);
        fund(&env, &mint, &owner, 100);
        let res = client.try_create_vault(
            &owner,
            &String::from_str(&env, "Past"),
            &10,
            &(now(&env) - 1),
        );
        assert!(matches!(res, Err(Ok(Error::InvalidTimestamp))));
    }

    #[test]
    fn create_rejects_non_positive_deposit() {
        let (env, client, _admin, _token, _mint) = setup();
        let owner = Address::generate(&env);
        let res = client.try_create_vault(
            &owner,
            &String::from_str(&env, "Empty"),
            &0,
            &(now(&env) + DAY),
        );
        assert!(matches!(res, Err(Ok(Error::InvalidAmount))));
    }

    #[test]
    fn deposit_keeps_unlock_unchanged() {
        let (env, client, _admin, _token, mint) = setup();
        let owner = Address::generate(&env);
        fund(&env, &mint, &owner, 5_000);
        let unlock = now(&env) + 60 * DAY;
        let id = client
            .create_vault(&owner, &String::from_str(&env, "Save"), &1_000, &unlock)
            ;

        client.deposit(&owner, &id, &500);
        let v = client.get_vault(&id);
        assert_eq!(v.balance, 1_500);
        assert_eq!(v.unlock_timestamp, unlock, "deposit must not move unlock");
    }

    #[test]
    fn deposit_non_owner_rejected() {
        let (env, client, _admin, _token, mint) = setup();
        let owner = Address::generate(&env);
        let attacker = Address::generate(&env);
        fund(&env, &mint, &owner, 1_000);
        fund(&env, &mint, &attacker, 1_000);
        let id = client
            .create_vault(&owner, &String::from_str(&env, "V"), &500, &(now(&env) + DAY))
            ;

        let res = client.try_deposit(&attacker, &id, &100);
        assert!(matches!(res, Err(Ok(Error::NotOwner))));
    }

    #[test]
    fn extend_only_pushes_forward() {
        let (env, client, _admin, _token, mint) = setup();
        let owner = Address::generate(&env);
        fund(&env, &mint, &owner, 1_000);
        let unlock = now(&env) + 10 * DAY;
        let id = client
            .create_vault(&owner, &String::from_str(&env, "E"), &100, &unlock)
            ;

        // zero-second extension is a "shorten" attempt → reject
        let res = client.try_extend_lock(&owner, &id, &0);
        assert!(matches!(res, Err(Ok(Error::ShortenForbidden))));

        let new_ts = client.extend_lock(&owner, &id, &(7 * DAY));
        assert_eq!(new_ts, unlock + 7 * DAY);
    }

    #[test]
    fn extend_non_owner_rejected() {
        let (env, client, _admin, _token, mint) = setup();
        let owner = Address::generate(&env);
        let attacker = Address::generate(&env);
        fund(&env, &mint, &owner, 1_000);
        let id = client
            .create_vault(&owner, &String::from_str(&env, "V"), &100, &(now(&env) + DAY))
            ;
        let res = client.try_extend_lock(&attacker, &id, &DAY);
        assert!(matches!(res, Err(Ok(Error::NotOwner))));
    }

    #[test]
    fn withdraw_blocked_while_locked() {
        let (env, client, _admin, _token, mint) = setup();
        let owner = Address::generate(&env);
        fund(&env, &mint, &owner, 1_000);
        let id = client
            .create_vault(&owner, &String::from_str(&env, "V"), &500, &(now(&env) + DAY))
            ;
        let res = client.try_withdraw(&owner, &id);
        assert!(matches!(res, Err(Ok(Error::StillLocked))));
    }

    #[test]
    fn withdraw_after_unlock_returns_full_balance() {
        let (env, client, _admin, token, mint) = setup();
        let owner = Address::generate(&env);
        fund(&env, &mint, &owner, 1_000);
        let unlock = now(&env) + DAY;
        let id = client
            .create_vault(&owner, &String::from_str(&env, "V"), &800, &unlock)
            ;
        assert_eq!(token.balance(&owner), 200);

        // Advance ledger past unlock.
        set_time(&env, unlock + 1);

        let withdrawn = client.withdraw(&owner, &id);
        assert_eq!(withdrawn, 800);
        assert_eq!(token.balance(&owner), 1_000);

        let v = client.get_vault(&id);
        assert!(v.withdrawn);
        assert_eq!(v.balance, 0);

        // Double-withdraw rejected.
        let res = client.try_withdraw(&owner, &id);
        assert!(matches!(res, Err(Ok(Error::AlreadyWithdrawn))));
    }

    #[test]
    fn withdraw_non_owner_rejected() {
        let (env, client, _admin, _token, mint) = setup();
        let owner = Address::generate(&env);
        let attacker = Address::generate(&env);
        fund(&env, &mint, &owner, 1_000);
        let unlock = now(&env) + DAY;
        let id = client
            .create_vault(&owner, &String::from_str(&env, "V"), &100, &unlock)
            ;
        set_time(&env, unlock + 1);
        let res = client.try_withdraw(&attacker, &id);
        assert!(matches!(res, Err(Ok(Error::NotOwner))));
    }

    #[test]
    fn list_owned_returns_only_callers_vaults() {
        let (env, client, _admin, _token, mint) = setup();
        let a = Address::generate(&env);
        let b = Address::generate(&env);
        fund(&env, &mint, &a, 1_000);
        fund(&env, &mint, &b, 1_000);
        client
            .create_vault(&a, &String::from_str(&env, "A1"), &10, &(now(&env) + DAY))
            ;
        client
            .create_vault(&a, &String::from_str(&env, "A2"), &20, &(now(&env) + DAY))
            ;
        client
            .create_vault(&b, &String::from_str(&env, "B1"), &30, &(now(&env) + DAY))
            ;
        assert_eq!(client.list_owned(&a).len(), 2);
        assert_eq!(client.list_owned(&b).len(), 1);
    }

    #[test]
    fn init_is_one_shot() {
        let (_env, client, _admin, _token, _mint) = setup();
        let dummy = Address::generate(&_env);
        let res = client.try_init(&dummy);
        assert!(matches!(res, Err(Ok(Error::AlreadyInitialised))));
    }
}
