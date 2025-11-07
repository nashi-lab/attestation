use starknet::ContractAddress;


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
    use core::panic_with_felt252;
    use core::poseidon::PoseidonTrait;
    use starknet::storage::{*, StoragePathEntry};
    use starknet::{ContractAddress, get_block_timestamp};
    use crate::schema_registry::{ISchemaRegistryDispatcher, ISchemaRegistryDispatcherTrait};
    use super::AttestationRequest;


    #[derive(Debug, Drop, Copy, Clone, starknet::Store)]
    pub struct Attestation {
        core: AttestationCore,
        reference_uid: Option<felt252>,
        revocation_time: u64,
    }

    #[derive(Debug, Copy, Hash, Drop, starknet::Store)]
    pub struct AttestationCore {
        attester: ContractAddress,
        recipient: ContractAddress,
        schema_uid: felt252,
        revocable: bool,
        creation_time: u64,
        revocation_time: u64,
    }


    #[storage]
    struct Storage {
        schema_registry: ISchemaRegistryDispatcher,
        attestation: Map<felt252, Option<Attestation>>,
        data: Map<felt252, Vec<felt252>>,
    }

    #[event]
    #[derive(Drop, Debug, PartialEq, starknet::Event)]
    pub enum Event {
        Attested: Attested,
    }

    #[derive(Drop, Debug, PartialEq, starknet::Event)]
    pub struct Attested {
        #[key]
        pub attester: ContractAddress,
        #[key]
        pub recipient: ContractAddress,
        #[key]
        pub schema_uid: felt252,
        pub uid: felt252,
    }


    pub mod Errors {
        pub const SCHEMA_RECORD_INVALID: felt252 = 'schema record invalid';
        pub const EXPIRATION_TIME_INVALID: felt252 = 'expiration time invalid';
        pub const IRREVOCABLE: felt252 = 'irrevocable';
        pub const ALREADY_EXISTS: felt252 = 'already exists';
        pub const REFERENCE_UID_INVALID: felt252 = 'reference uid invalid';
        pub const SCHEMA_UID_INVALID: felt252 = 'schema uid invalid';
        pub const REVOKER_INVALID: felt252 = 'revoker invalid';
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

        fn make(
            ref self: ContractState,
            attester: ContractAddress,
            schema_uid: felt252,
            request: @AttestationRequest,
            salt: felt252,
        ) {
            let schema_record = self
                .schema_registry
                .read()
                .get_schema(schema_uid)
                .expect(Errors::SCHEMA_RECORD_INVALID);

            assert(schema_record.revocable || !*request.revocable, Errors::IRREVOCABLE);

            assert(
                request.expiration_time.is_none()
                    || request.expiration_time.unwrap() > get_block_timestamp(),
                Errors::EXPIRATION_TIME_INVALID,
            );

            let attestation_core = AttestationCore {
                attester,
                recipient: *request.recipient,
                schema_uid,
                revocable: *request.revocable,
                creation_time: get_block_timestamp(),
                revocation_time: 0,
            };

            let uid = self.hash(@attestation_core, salt);

            match self.attestation.entry(uid).read() {
                Some(_) => { panic_with_felt252(Errors::ALREADY_EXISTS); },
                None => {
                    if let Some(val) = *request.reference_uid {
                        assert(
                            self.attestation.entry(val).read().is_some(),
                            Errors::REFERENCE_UID_INVALID,
                        );

                        let attestation = Attestation {
                            core: attestation_core,
                            reference_uid: *request.reference_uid,
                            revocation_time: 0,
                        };

                        self.attestation.entry(uid).write(Some(attestation));

                        for e in request.data.into_iter() {
                            self.data.entry(uid).push(*e);
                        }

                        self
                            .emit(
                                Attested {
                                    attester, recipient: *request.recipient, schema_uid, uid,
                                },
                            );
                    }
                },
            }
        }
    }
}

