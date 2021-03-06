All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

# [0.12.1](https://github.com/nervosnetwork/ckb-sdk-ruby/compare/v0.12.0...v0.12.1) (2019-05-18)


### Bug Fixes

* fix for gather_inputs when diff = 0 ([e690a71](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/e690a71))


### Features

* persistent http client ([041eb60](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/041eb60))


# [0.12.0](https://github.com/nervosnetwork/ckb-sdk-ruby/compare/v0.11.0...v0.12.0) (2019-05-18)


### Bug Fixes

* fix cell exception ([df5a81d](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/df5a81d))
* fix dao generation bug ([91f40ee](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/91f40ee))
* fix types ([aeb03fb](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/aeb03fb))
* fix witnesses_root ([fb26eac](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/fb26eac))
* remove check self in from_h ([8758713](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/8758713))
* return if hash.nil? in from_h ([28b61cb](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/28b61cb))
* script test ([2838ed8](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/2838ed8))


### Code Refactoring

* rename to system_script_code_hash ([036c6bd](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/036c6bd))


### Features

* add `dry_run_transaction` RPC ([4501a69](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/4501a69))
* add `get_epoch_by_number` RPC ([51eb43f](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/51eb43f))
* add `get_peers` & `tx_pool_info` RPCs ([77ec29c](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/77ec29c))
* add `TxPoolInfo` type ([0f257a4](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/0f257a4))
* add data setter in `Types::Witness` ([4774ead](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/4774ead))
* add epoch type and add `get_current_epoch` RPC ([035d43e](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/035d43e))
* add peer and address_info types ([933da45](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/933da45))
* add state RPCs ([2ec5580](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/2ec5580))
* add types ([1347073](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/1347073))
* follow RPCs to set number to string ([4891865](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/4891865))
* Generalize OutPoint struct to reference headers ([253f96b](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/253f96b))
* keep der signature ([e54e5d2](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/e54e5d2))
* NervosDAO integration ([0f6ec28](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/0f6ec28))
* remove unneeded blake2b hash ([fdb1a42](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/fdb1a42))
* Test transaction sign ([ab45e04](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/ab45e04))
* update SDK per lock script changes ([29ad6ae](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/29ad6ae))
* update system script cell index to 1 ([6c0759f](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/6c0759f))
* use fixed code_hash and out_point in testnet mode ([adb47f4](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/adb47f4))
* using genesis block first transaction second output as system script ([518a124](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/518a124))
* using real tx_hash after sign ([373e38a](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/373e38a))


### BREAKING CHANGES

* `system_script_cell_hash` => `system_script_code_hash`
* trace RPCs are deleted
* `api.tx_pool_info` returns `TxPoolInfo` instead of `Hash`
* `local_node_info` and `get_peers` return types instead of Hash
* `OutPoint` structure changed


# [v0.11.0](https://github.com/nervosnetwork/ckb-sdk-ruby/compare/v0.10.0...v0.11.0) (2019-05-14)


### Features

* add RPC `get_block_by_number` ([c410ec3](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/c410ec3))


### BREAKING CHANGES

* rename variables ([a59158b](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/a59158b))
  * rename OutPoint `hash` to `tx_hash`
  * rename Script `binary_hash` to `code_hash`
  * rename Input `valid_since` to `since`
  * rename Block `commit_transactions` to `transactions`
* update test of `get_transaction` for structure changes ([3b8c637](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/3b8c637))
* use shannon as capacity unit ([9a013ae](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/9a013ae))


# [v0.10.0](https://github.com/nervosnetwork/ckb-sdk-ruby/compare/v0.9.0...v0.10.0) (2019-05-06)

### Bug Fixes

* capacity in RPC interface changed to string ([d8d3d05](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/d8d3d05))
* remove version from script ([9348185](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/9348185))


### Features

* use 0x-prefix hex string represent block assembler args ([171e08e](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/171e08e))



# [v0.9.0](https://github.com/nervosnetwork/ckb-sdk-ruby/compare/v0.8.0...v0.9.0) (2019-04-22)

### Bug Fixes

* fix code per CKB's latest changes ([7505edf](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/7505edf))
* fix segwit logic ([460caab](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/460caab))
* Fix tests ([0afc5bc](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/0afc5bc))
* fix the bug in transaction generation ([ca33aa7](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/ca33aa7))
* Fix the bug that shared lock gets modified when sending tx ([21092de](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/21092de))
* fix witnesses format ([d87d9d8](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/d87d9d8))
* remove duplicated lock in wallet ([e814920](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/e814920))


### Features

* Address format implementation ([4c543bf](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/4c543bf))
* support segwit ([6959395](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/6959395))
* Upgrade SDK with latest CKB changes ([ae5c1c5](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/ae5c1c5))



# [v0.8.0](https://github.com/nervosnetwork/ckb-sdk-ruby/compare/v0.7.0...v0.8.0) (2019-04-08)

### Bug Fixes

* fix tx rpc tests logic



# [v0.7.0](https://github.com/nervosnetwork/ckb-sdk-ruby/tree/v0.7.0) (2019-03-22)


### Features

* add basic wallet ([2e14b49](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/2e14b49))
* add rpc interface ([a4b1f47](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/a4b1f47))
* init project ([1cb5623](https://github.com/nervosnetwork/ckb-sdk-ruby/commit/1cb5623))
* extract from ([ckb-demo-ruby](https://github.com/nervosnetwork/ckb-demo-ruby))
