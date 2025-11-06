use starknet::storage::Vec;
use starknet::ContractAddress;

#[derive(Debug, Copy, Hash, Drop, starknet::Store)]
pub struct AttestationCore {
    attester: ContractAddress,
    recipient: ContractAddress,
    schema_uid: felt252,
    revocable: bool,
    creation_time: u64,
    revocation_time: u64,
}

#[starknet::storage_node]
pub struct Attestation {
    core: AttestationCore,
    reference_uid: Option<felt252>,
    revocation_time: u64,
    data: Vec<felt252>,
}


#[derive(Debug)]
pub struct AttestationRequest {
    recipient: ContractAddress,
    expiration_time: Option<u64>,
    revocable: bool,
    reference_uid: Option<felt252>,
    data: Array<felt252>,
}


pub trait IAttestation<TState> {}


#[starknet::contract]
mod Attestations {
    use core::hash::{HashStateExTrait, HashStateTrait};
    use core::poseidon::PoseidonTrait;
    use starknet::storage::{
        Map, StoragePointerReadAccess
        StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, get_block_timestamp};
    use crate::schema_registry::{ISchemaRegistryDispatcher, ISchemaRegistryDispatcherTrait};
    use super::{AttestationCore, AttestationRequest};

    #[storage]
    struct Storage {
        schema_registry: ISchemaRegistryDispatcher,
        attestation: Map<felt252, Option<Attestation>>,
    }

    pub mod Errors {
        pub const SCHEMA_RECORD_INVALID: felt252 = 'A: schema record invalid';
        pub const EXPIRATION_TIME_INVALID: felt252 = 'A: expiration time invalid';
        pub const IRREVOCABLE: felt252 = 'A: irrevocable';
    }


    #[constructor]
    fn constructor(ref self: ContractState, schema_registry_addr: ContractAddress) {
        self
            .schema_registry
            .write(ISchemaRegistryDispatcher { contract_address: schema_registry_addr });
    }

    #[generate_trait]
    impl Internal of InternalTrait {
        fn hash(self: @ContractState, att: @AttestationCore, salt: felt252) -> felt252 {
            PoseidonTrait::new().update_with(*att).update(salt).finalize()
        }

        fn attest(
            ref self: @ContractState,
            attester: ContractAddress,
            schema_uid: felt252,
            requests: @Array<AttestationRequest>,
            salt: felt252,
        ) {
            let schema_record = self
                .schema_registry
                .read()
                .get_schema(schema_uid)
                .expect(Errors::SCHEMA_RECORD_INVALID);

            for request in requests.into_iter() {
                assert(
                    *request.expiration_time != None
                        && request.expiration_time.unwrap() <= get_block_timestamp(),
                    Errors::EXPIRATION_TIME_INVALID,
                );

                assert(!schema_record.revocable && *request.revocable, Errors::IRREVOCABLE);

                let attestation = AttestationCore {
                    attester: attester,
                    recipient: *request.recipient,
                    schema_uid: schema_uid,
                    revocable: *request.revocable,
                    creation_time: get_block_timestamp(),
                    revocation_time: 0,
                };

                let uid = self.hash(@attestation, salt);
            }
        }
    }
}

