use starknet::ContractAddress;

#[derive(Debug, Serde, Drop, Clone, PartialEq, starknet::Store)]
pub struct SchemaRecord {
    pub resolver: ContractAddress,
    pub revocable: bool,
    pub schema: ByteArray,
}


#[starknet::interface]
pub trait ISchemaRegistry<TState> {
    fn register(
        ref self: TState, resolver: ContractAddress, revocable: bool, schema: ByteArray,
    ) -> felt252;
    fn get_schema(self: @TState, uid: felt252) -> Option<SchemaRecord>;
}


#[starknet::contract]
mod SchemaRegistry {
    use core::hash::{HashStateExTrait, HashStateTrait};
    use core::panic_with_felt252;
    use core::poseidon::{PoseidonTrait, poseidon_hash_span};
    use starknet::ContractAddress;
    use starknet::storage::{
        Map, StoragePathEntry, StoragePointerReadAccess, StoragePointerWriteAccess,
    };
    use super::SchemaRecord;

    #[storage]
    struct Storage {
        registry: Map<felt252, Option<SchemaRecord>>,
    }


    pub mod Errors {
        pub const ALREADY_EXISTS: felt252 = 'SR: already exists';
    }

    #[abi(embed_v0)]
    impl SchemaRegistry of super::ISchemaRegistry<ContractState> {
        fn get_schema(self: @ContractState, uid: felt252) -> Option<SchemaRecord> {
            self.registry.entry(uid).read()
        }

        fn register(
            ref self: ContractState, resolver: ContractAddress, revocable: bool, schema: ByteArray,
        ) -> felt252 {
            let record = SchemaRecord { resolver, revocable, schema };

            let uid = self.hash(record.clone());

            match self.get_schema(uid) {
                Some(_) => { panic_with_felt252(Errors::ALREADY_EXISTS); },
                None => { self.registry.entry(uid).write(Some(record)); },
            }

            uid
        }
    }


    #[generate_trait]
    impl Internal of InternalTrait {
        fn hash(self: @ContractState, record: SchemaRecord) -> felt252 {
            let mut output_arr = array![];
            record.schema.serialize(ref output_arr);
            PoseidonTrait::new()
                .update_with(record.resolver)
                .update_with(record.revocable)
                .update(poseidon_hash_span(output_arr.span()))
                .finalize()
        }
    }
}
