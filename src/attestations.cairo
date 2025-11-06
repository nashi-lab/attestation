use starknet::ContractAddress;

#[derive(Debug, Copy, Hash, Drop)]
pub struct AttestationCore {
    attester: ContractAddress,
    recipient: ContractAddress,
    schema_uid: felt252,
    reference_uid: felt252,
    revocable: bool,
    creation_time: u64,
    revocation_time: u64,
}

#[derive(Debug, Drop)]
pub struct Attestation {
    core: AttestationCore,
    revocation_time: u64,
    data: Array<felt252>,
}


#[derive(Debug)]
pub struct AttestationRequest {
    recipient: ContractAddress,
    expiration_time: u64,
    revocable: bool,
    ref_uid: felt252,
    data: Array<felt252>,
}


pub trait IAttestation<TState> {}


#[starknet::contract]
mod Attestations {
    use core::hash::{HashStateExTrait, HashStateTrait};
    use core::poseidon::PoseidonTrait;
    use starknet::ContractAddress;
    use starknet::storage::StoragePointerWriteAccess;
    use super::AttestationCore;

    #[storage]
    struct Storage {
        schema_registry: ContractAddress,
    }


    #[constructor]
    fn constructor(ref self: ContractState, schema_registry_addr: ContractAddress) {
        self.schema_registry.write(schema_registry_addr);
    }

    #[generate_trait]
    impl Internal of InternalTrait {
        fn hash(self: @ContractState, att: @AttestationCore, salt: felt252) -> felt252 {
            PoseidonTrait::new().update_with(*att).update(salt).finalize()
        }
    }
}

