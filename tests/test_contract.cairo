use attestation::schema_registry::{
    ISchemaRegistryDispatcher, ISchemaRegistryDispatcherTrait, SchemaRecord,
};
use core::hash::{HashStateExTrait, HashStateTrait};
use core::poseidon::{PoseidonTrait, poseidon_hash_span};
use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};
use starknet::ContractAddress;


fn deploy_contract(name: ByteArray) -> ContractAddress {
    let contract = declare(name).unwrap().contract_class();
    let (contract_address, _) = contract.deploy(@ArrayTrait::new()).unwrap();
    contract_address
}

fn get_uid(resolver: ContractAddress, revocable: bool, schema: @ByteArray) -> felt252 {
    let mut output_arr = array![];
    schema.serialize(ref output_arr);
    PoseidonTrait::new()
        .update_with(resolver)
        .update_with(revocable)
        .update(poseidon_hash_span(output_arr.span()))
        .finalize()
}


#[test]
fn test_register() {
    let contract_address = deploy_contract("SchemaRegistry");
    let dispatcher = ISchemaRegistryDispatcher { contract_address };

    let addr = 0x4718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d;
    let resolver: ContractAddress = addr.try_into().unwrap();
    let revocable = false;
    let schema: ByteArray = "felt252 uid, ByteArray reason";

    let expected_uid = get_uid(resolver, revocable, @schema);

    let uid = dispatcher.register(resolver, revocable, schema.clone());
    assert_eq!(uid, expected_uid, "uid mismatch");
    let record = SchemaRecord { resolver, revocable, schema };

    let schema_record = dispatcher.get_schema(uid).unwrap();

    assert_eq!(schema_record, record, "schema mismatch");
}

