// Copyright © Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::module_and_script_storage::module_storage::AptosModuleStorage;
use ambassador::Delegate;
use aptos_types::state_store::{state_key::StateKey, state_value::StateValueMetadata, StateView};
use bytes::Bytes;
use move_binary_format::{
    errors::{PartialVMResult, VMResult},
    file_format::CompiledScript,
    CompiledModule,
};
use move_core_types::{account_address::AccountAddress, identifier::IdentStr, metadata::Metadata};
use move_vm_runtime::{
    ambassador_impl_CodeStorage, ambassador_impl_ModuleStorage,
    ambassador_impl_WithRuntimeEnvironment, AsUnsyncCodeStorage, BorrowedOrOwned, CodeStorage,
    Module, ModuleStorage, RuntimeEnvironment, Script, UnsyncCodeStorage, UnsyncModuleStorage,
    WithRuntimeEnvironment,
};
use move_vm_types::{code::ModuleBytesStorage, module_storage_error};
use std::sync::Arc;

/// Avoids orphan rule to implement [ModuleBytesStorage] for [StateView].
struct StateViewAdapter<'s, S> {
    state_view: BorrowedOrOwned<'s, S>,
}

impl<'s, S: StateView> ModuleBytesStorage for StateViewAdapter<'s, S> {
    fn fetch_module_bytes(
        &self,
        address: &AccountAddress,
        module_name: &IdentStr,
    ) -> VMResult<Option<Bytes>> {
        let state_key = StateKey::module(address, module_name);
        self.state_view
            .get_state_value_bytes(&state_key)
            .map_err(|e| module_storage_error!(address, module_name, e))
    }
}

/// A (not thread-safe) implementation of code storage on top of a state view. It is never built
/// directly by clients - only via [AsAptosCodeStorage] trait. Can be used to resolve both modules
/// and cached scripts.
#[derive(Delegate)]
#[delegate(
    WithRuntimeEnvironment,
    where = "S: StateView, E: WithRuntimeEnvironment"
)]
#[delegate(ModuleStorage, where = "S: StateView, E: WithRuntimeEnvironment")]
#[delegate(CodeStorage, where = "S: StateView, E: WithRuntimeEnvironment")]
pub struct AptosCodeStorageAdapter<'s, S, E> {
    storage: UnsyncCodeStorage<UnsyncModuleStorage<'s, StateViewAdapter<'s, S>, E>>,
}

impl<'s, S: StateView, E: WithRuntimeEnvironment> AptosCodeStorageAdapter<'s, S, E> {
    /// Creates new instance of [AptosCodeStorageAdapter] built on top of the passed state view and
    /// the provided runtime environment.
    fn from_borrowed(state_view: &'s S, runtime_environment: E) -> Self {
        let adapter = StateViewAdapter {
            state_view: BorrowedOrOwned::Borrowed(state_view),
        };
        let storage = adapter.into_unsync_code_storage(runtime_environment);
        Self { storage }
    }

    /// Creates new instance of [AptosCodeStorageAdapter] capturing the passed state view and the
    /// provided environment.
    fn from_owned(state_view: S, runtime_environment: E) -> Self {
        let adapter = StateViewAdapter {
            state_view: BorrowedOrOwned::Owned(state_view),
        };
        let storage = adapter.into_unsync_code_storage(runtime_environment);
        Self { storage }
    }
}

impl<'s, S: StateView, E: WithRuntimeEnvironment> AptosModuleStorage
    for AptosCodeStorageAdapter<'s, S, E>
{
    fn fetch_state_value_metadata(
        &self,
        address: &AccountAddress,
        module_name: &IdentStr,
    ) -> PartialVMResult<Option<StateValueMetadata>> {
        let state_key = StateKey::module(address, module_name);
        Ok(self
            .storage
            .module_storage()
            .byte_storage()
            .state_view
            .get_state_value(&state_key)
            .map_err(|err| module_storage_error!(address, module_name, err).to_partial())?
            .map(|state_value| state_value.into_metadata()))
    }
}

/// Allows to treat the state view as a code storage with scripts and modules. The main use case is
/// when a transaction or a Move function has to be executed outside the long-living environment or
/// block executor, e.g., for single transaction simulation, in Aptos debugger, etc.
pub trait AsAptosCodeStorage<'s, S, E> {
    fn as_aptos_code_storage(&'s self, runtime_environment: E)
        -> AptosCodeStorageAdapter<'s, S, E>;

    fn into_aptos_code_storage(self, runtime_environment: E) -> AptosCodeStorageAdapter<'s, S, E>;
}

impl<'s, S: StateView, E: WithRuntimeEnvironment> AsAptosCodeStorage<'s, S, E> for S {
    fn as_aptos_code_storage(&'s self, runtime_environment: E) -> AptosCodeStorageAdapter<S, E> {
        AptosCodeStorageAdapter::from_borrowed(self, runtime_environment)
    }

    fn into_aptos_code_storage(self, runtime_environment: E) -> AptosCodeStorageAdapter<'s, S, E> {
        AptosCodeStorageAdapter::from_owned(self, runtime_environment)
    }
}
