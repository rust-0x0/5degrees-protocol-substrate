#![cfg_attr(not(feature = "std"), no_std)]

use ink_lang as ink;

// type Balance = <ink_env::DefaultEnvironment as ink_env::Environment>::Balance;
// The ERC-1155 result types.
// pub type Result<T> = core::result::Result<T, Error>;
#[ink::contract]
mod five_degrees {
    use ink_lang::codegen::EmitEvent;
    // use ink_prelude::format;
    use erc1155::{
        erc1155::Burn, erc1155::BurnBatch, erc1155::Mint, erc1155::MintBatch, erc1155::Uri,
        ContractRef, TokenId,
    };
    use ink_env::format;
    use ink_prelude::string::String;
    use ink_prelude::vec;
    use ink_prelude::vec::Vec;
    use ink_storage::{
        traits::{PackedLayout, SpreadAllocate, SpreadLayout},
        Mapping,
    };
    const CONTRACT_INIT_BALANCE: u128 = 1000 * 1_000_000_000_000;

    /// It records how many tickets there are in a block
    #[derive(scale::Encode, scale::Decode, Clone, SpreadLayout, PackedLayout)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink_storage::traits::StorageLayout)
    )]
    #[derive(Debug)]
    pub struct TokenURIInfo {
        name: String,
        image: String,
        max_supply: u128,
        properties: String,
    }

    #[derive(scale::Encode, scale::Decode, Clone, SpreadLayout, PackedLayout)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink_storage::traits::StorageLayout)
    )]
    #[derive(Debug)]
    pub struct TokenURIInfoJson {
        name: String,
        image: String,
        max_supply: u128,
        token_supply: u128,
        total_balance: u128,
        properties: String,
    }
    /// Defines the storage of your contract.
    /// Add new fields to the below struct in order
    /// to add new static storage fields to your contract.
    #[ink(storage)]
    #[derive(SpreadAllocate)]
    pub struct FiveDegrees {
        /// Stores a single `bool` value on the storage.
        _uri: Mapping<AccountId, TokenURIInfo>,
        _token_supply: Mapping<AccountId, Balance>,
        _total_balance: Mapping<AccountId, Balance>,
        pay_proxy: AccountId,
        contract_addr: AccountId,
    }
    //Web3 Ascii code 87+101+98+51 = 8195
    const _MAX_SUPPLY: u128 = 8195;

    /// Errors that can occur upon calling this contract.
    #[derive(Copy, Clone, Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(::scale_info::TypeInfo))]
    pub enum Error {
        /// Returned if the call failed.
        TransactionFailed,
    }

    impl FiveDegrees {
        /// Constructor that initializes the `bool` value to the given `init_value`.
        #[ink(constructor)]
        pub fn new(version: u32, code_hash: Hash) -> Self {
            ink_lang::utils::initialize_contract(|contract: &mut Self| {
                contract._uri.insert(
                    Self::env().account_id(),
                    &TokenURIInfo {
                        name: String::new(),
                        image: String::new(),
                        max_supply: 2022,
                        properties: String::new(),
                    },
                );
                #[cfg(not(test))]
                {
                    // let version = self::length;
                    let salt = version.to_le_bytes();
                    let instance_params = ContractRef::new()
                        .endowment(CONTRACT_INIT_BALANCE)
                        .code_hash(code_hash)
                        .salt_bytes(salt)
                        .params();
                    let init_result = ink_env::instantiate_contract(&instance_params);
                    let contract_addr =
                        init_result.expect("failed at instantiating the `Erc20` contract");

                    contract.contract_addr = contract_addr;
                }
            })
        }

        /// A message that can be called on instantiated contracts.
        /// This one flips the value of the stored `bool` from `true`
        /// to `false` and vice versa.
        #[ink(message)]
        pub fn set_protocol_info(&mut self, name: String, image: String, properties: String) {
            let token_id = self.env().account_id(); // self.account_id_to_token_id(self.env().account_id());
            let mut t = self._uri.get(&token_id).unwrap_or(TokenURIInfo {
                name: String::new(),
                image: String::new(),
                max_supply: 2022,
                properties: String::new(),
            });
            t.name = name;
            t.image = image;
            t.properties = properties;
            self._uri.insert(token_id, &t);
            self.env().emit_event(Uri {
                value: self.uri(token_id),
                token_id: self.account_id_to_token_id(self.env().account_id()),
            });
        }

        /// Simply returns the current value of our `bool`.
        fn uri(&self, token_id: AccountId) -> String {
            let mut info = self._uri.get(&token_id).unwrap();
            if info.max_supply == 0 {
                info.max_supply = _MAX_SUPPLY;
            }
            let followers = self._token_supply.get(&token_id).unwrap_or(0);
            let followings = self._total_balance.get(&token_id).unwrap_or(0);
            use scale::Encode;
            let json = TokenURIInfoJson {
                name: info.name,
                image: info.image,
                max_supply: info.max_supply,
                token_supply: followers,
                total_balance: followings,
                properties: info.properties,
            };
            String::from_utf8(json.encode()).unwrap()
            // string memory json = Base64.encode(
            //     bytes(
            //         string(
            //             abi.encodePacked(
            //                 '{ "name": "',
            //                 info.name,
            //                 '", ',
            //                 '"image": "',
            //                 info.image,
            //                 '", ',
            //                 '"maxSupply": "',
            //                 info.maxSupply.toString(),
            //                 '", ',
            //                 '"tokenSupply": "',
            //                 followers.toString(),
            //                 '", ',
            //                 '"totalBalance": "',
            //                 followings.toString(),
            //                 '", ',
            //                 '"properties": "',
            //                 info.properties,
            //                 '" }'
            //             )
            //         )
            //     )
            // );
            // return string(abi.encodePacked("data:application/json;base64,", json));
        }
        #[ink(message)]
        pub fn base_info(&self, account: AccountId) -> (String, String) {
            let info = self._uri.get(&account).unwrap();
            let name = info.name;
            let image = info.image;
            (name, image)
        }
        #[ink(message)]
        pub fn metrics(&self, account: AccountId) -> (u128, u128) {
            let token_supply = self._token_supply.get(&account).unwrap();
            let total_balance = self._total_balance.get(&account).unwrap();
            (token_supply, total_balance)
        }
        #[ink(message)]
        pub fn set_pay_proxy(&mut self, proxy: AccountId) {
            //onlyOwner
            self.pay_proxy = proxy;
        }
        #[ink(message)]
        pub fn set_info(&mut self, name: String, image: String, properties: String) {
            let token_id = self.env().caller();
            let mut t = self._uri.get(&token_id).unwrap_or(TokenURIInfo {
                name: String::new(),
                image: String::new(),
                max_supply: 2022,
                properties: String::new(),
            });
            t.name = name;
            t.image = image;
            t.properties = properties;
            self._uri.insert(token_id, &t);
            // emit Uri(uri(token_id), token_id);
            self.env().emit_event(Uri {
                value: self.uri(token_id),
                token_id: self.account_id_to_token_id(token_id),
            });
        }
        fn pay_proxy_call(&mut self, account: AccountId, new_max: u128, the_max: u128) {
            let (token, receiver, amount) = self.query_pay(account, new_max, the_max);
            if amount > 0 {
                if token == AccountId::default() {
                    let value = self.env().transferred_value();
                    assert!(value >= amount, "5Degrees: invalid msg.value");
                    // payable(receiver).transfer(msg.value);
                    if self.env().transfer(receiver, value).is_err() {
                        panic!(
                    "requested transfer failed. this can be the case if the contract does not\
                     have sufficient free funds or if the transfer would have brought the\
                     contract's balance below minimum balance.")
                    }
                } else {
                    self.token_call(
                        token,
                        [0x0b, 0x39, 0x6f, 0x18].to_vec(),
                        account,
                        receiver,
                        amount,
                    );
                }
            }
        }
        fn query_pay(
            &self,
            account: AccountId,
            new_max: u128,
            _the_max: u128,
        ) -> (AccountId, AccountId, u128) {
            let (token, receiver, amount) = (account, account, new_max);
            //  (address token, address receiver, uint256 amount) = IPayProxy(PAY_PROXY).queryPay(msg.sender, newMax, theMax);
            (token, receiver, amount)
        }
        fn token_call(
            &mut self,
            token: AccountId,
            selector: Vec<u8>,
            account: AccountId,
            receiver: AccountId,
            amount: u128,
        ) {
            #[cfg(not(test))]
            {
                use ink_env::call::{build_call, Call, ExecutionInput};
                let transferred_value = Balance::default();
                let gas_limit = 0;
                // let contracts_selector = [0x80, 0x05, 0xa4, 0x70];
                // (bool success, bytes memory data) = token.call(abi.encodeWithSelector(0x23b872dd, msg.sender, receiver, amount));
                let selector = [selector[0], selector[1], selector[2], selector[3]]; // [0x0b, 0x39, 0x6f, 0x18];
                let result = build_call::<<Self as ::ink_lang::reflect::ContractEnv>::Env>()
                    .call_type(
                        Call::new()
                            .callee(token)
                            .gas_limit(gas_limit)
                            .transferred_value(transferred_value),
                    )
                    .exec_input(
                        ExecutionInput::new(selector.into())
                            .push_arg(account)
                            .push_arg(receiver)
                            .push_arg(amount),
                    )
                    .returns::<()>()
                    .fire()
                    .map_err(|_| Error::TransactionFailed);
                assert!(result.is_ok(), "transfer_from_failed");
            }
        }

        #[ink(message, payable)]
        pub fn increase_max_supply(&mut self, new_max: u128) {
            let token_id = self.env().caller();
            let mut info = self._uri.get(&token_id).unwrap_or(TokenURIInfo {
                name: String::new(),
                image: String::new(),
                max_supply: 2022,
                properties: String::new(),
            });
            if info.max_supply == 0 {
                info.max_supply = _MAX_SUPPLY;
                self._uri.insert(&token_id, &info);
            }
            let the_max = info.max_supply;
            assert!(the_max < new_max, "5Degrees: support increase only");
            if self.pay_proxy != AccountId::default() {
                self.pay_proxy_call(token_id, new_max, the_max);
            }
            info.max_supply = new_max;
            self._uri.insert(token_id, &info);
            self.env().emit_event(Uri {
                value: self.uri(token_id),
                token_id: self.account_id_to_token_id(token_id),
            });
        }

        #[ink(message)]
        pub fn decrease_max_supply(&mut self, new_max: u128) {
            let token_id = self.env().caller();
            let mut info = self._uri.get(&token_id).unwrap_or(TokenURIInfo {
                name: String::new(),
                image: String::new(),
                max_supply: 2022,
                properties: String::new(),
            });
            if info.max_supply == 0 {
                info.max_supply = _MAX_SUPPLY;
            }
            assert!(
                self._token_supply.get(&token_id).unwrap() <= new_max,
                "5Degrees: support increase only"
            );
            assert!(info.max_supply > new_max, "5Degrees: support increase only");

            info.max_supply = new_max;
            self._uri.insert(token_id, &info);
            self.env().emit_event(Uri {
                value: self.uri(token_id),
                token_id: self.account_id_to_token_id(token_id),
            });
        }
        #[ink(message)]
        pub fn mint(&mut self, account: AccountId) {
            let operator = self.env().caller();
            self._internal_mint(account, operator);
        }
        #[ink(message)]
        pub fn mint_by_origin(&mut self, account: AccountId, operator: AccountId) {
            // let operator = self.env().caller();
            //assert!(self.env().caller_is_origin());
            self._internal_mint(account, operator);
        }
        fn _internal_mint(&mut self, account: AccountId, operator: AccountId) {
            let token_id = self.account_id_to_token_id(account);
            assert!(operator != account, "5Degrees: cannot mint your own NFT");
            #[cfg(not(test))]
            {
                let erc1155_instance: ContractRef =
                    ink_env::call::FromAccountId::from_account_id(self.contract_addr);
                assert!(
                    erc1155_instance.balance_of(operator, token_id) == 0,
                    "5Degrees: already minted"
                );
            }

            let mut info = self._uri.get(&account).unwrap();
            let token_supply = self._token_supply.get(&account).unwrap();
            if info.max_supply == 0 {
                info.max_supply = _MAX_SUPPLY;
                self._uri.insert(&account, &info);
            } else {
                assert!(
                    token_supply + 1 <= info.max_supply,
                    "5Degrees: larger than max supply"
                );
            }
            #[cfg(not(test))]
            {
                let mut erc1155_instance: ContractRef =
                    ink_env::call::FromAccountId::from_account_id(self.contract_addr);
                let _r = erc1155_instance.mint_to(operator, token_id, 1);
            }
            let total_balance = self._total_balance.get(&operator).unwrap();
            self._total_balance.insert(&account, &(total_balance + 1));
            self._token_supply.insert(&account, &(token_supply + 1));
            // emit Mint(account, operator, token_id);
            self.env().emit_event(Mint {
                account,
                owner: operator,
                token_id,
            });
        }

        #[ink(message)]
        pub fn mint_batch(&mut self, account: Vec<AccountId>) {
            let operator = self.env().caller();
            self._internal_mint_batch(operator, account);
        }
        #[ink(message)]
        pub fn mint_batch_by_origin(&mut self, accounts: Vec<AccountId>) {
            let operator = self.env().caller();
            assert!(self.env().caller_is_origin());
            self._internal_mint_batch(operator, accounts);
        }
        fn _internal_mint_batch(&mut self, operator: AccountId, accounts: Vec<AccountId>) {
            let mut ids = Vec::new();
            let mut amounts = Vec::new();
            for &account in &accounts {
                let token_id = self.account_id_to_token_id(account);
                let mut info = self._uri.get(&account).unwrap();
                let token_supply = self._token_supply.get(&account).unwrap();
                if operator == account || token_supply + 1 > info.max_supply {
                    continue;
                }
                #[cfg(not(test))]
                {
                    let erc1155_instance: ContractRef =
                        ink_env::call::FromAccountId::from_account_id(self.contract_addr);
                    if erc1155_instance.balance_of(operator, token_id) > 0 {
                        continue;
                    }
                }
                if info.max_supply == 0 {
                    info.max_supply = _MAX_SUPPLY;
                    self._uri.insert(&account, &info);
                }
                let total_balance = self._total_balance.get(&operator).unwrap();
                self._total_balance.insert(&account, &(total_balance + 1));
                self._token_supply.insert(&account, &(token_supply + 1));
                ids.push(token_id);
                amounts.push(1);
            }
            #[cfg(not(test))]
            {
                let mut erc1155_instance: ContractRef =
                    ink_env::call::FromAccountId::from_account_id(self.contract_addr);
                let _r = erc1155_instance.mint_to_batch(operator, ids.clone(), amounts);
            }
            self.env().emit_event(MintBatch {
                accounts,
                owner: operator,
                token_ids: ids,
            });
        }

        #[ink(message)]
        pub fn burn(&mut self, account: AccountId) {
            let operator = self.env().caller();
            self._internal_burn(account, operator);
        }
        #[ink(message)]
        pub fn burn_by_origin(&mut self, account: AccountId, operator: AccountId) {
            // let operator = self.env().caller();
            //assert!(self.env().caller_is_origin());
            self._internal_burn(account, operator);
        }
        fn _internal_burn(&mut self, account: AccountId, operator: AccountId) {
            let token_id = self.account_id_to_token_id(account);
            #[cfg(not(test))]
            {
                let mut erc1155_instance: ContractRef =
                    ink_env::call::FromAccountId::from_account_id(self.contract_addr);
                assert!(
                    erc1155_instance.balance_of(operator, token_id) > 0,
                    "5Degrees:  token not existed"
                );
                erc1155_instance.burn(operator, token_id, 1);
            }
            let token_supply = self._token_supply.get(&account).unwrap();
            let total_balance = self._total_balance.get(&operator).unwrap();
            self._total_balance.insert(&account, &(total_balance - 1));
            self._token_supply.insert(&operator, &(token_supply - 1));
            self.env().emit_event(Burn {
                account,
                owner: operator,
                token_id,
            });
        }

        #[ink(message)]
        pub fn burn_batch(&mut self, account: Vec<AccountId>) {
            let operator = self.env().caller();
            self._internal_burn_batch(operator, account);
        }
        #[ink(message)]
        pub fn burn_batch_by_origin(&mut self, operator: AccountId, accounts: Vec<AccountId>) {
            // let operator = self.env().caller();
            //assert!(self.env().caller_is_origin());
            self._internal_burn_batch(operator, accounts);
        }
        fn _internal_burn_batch(&mut self, operator: AccountId, accounts: Vec<AccountId>) {
            let mut ids = Vec::new();
            let mut amounts = Vec::new();
            for &account in &accounts {
                let token_id = self.account_id_to_token_id(account);
                #[cfg(not(test))]
                {
                    let erc1155_instance: ContractRef =
                        ink_env::call::FromAccountId::from_account_id(self.contract_addr);
                    if erc1155_instance.balance_of(operator, token_id) == 0 {
                        continue;
                    }
                }
                let token_supply = self._token_supply.get(&account).unwrap();
                let total_balance = self._total_balance.get(&operator).unwrap();
                self._total_balance.insert(&account, &(total_balance - 1));
                self._token_supply.insert(&account, &(token_supply - 1));
                ids.push(token_id);
                amounts.push(1);
            }
            #[cfg(not(test))]
            {
                let mut erc1155_instance: ContractRef =
                    ink_env::call::FromAccountId::from_account_id(self.contract_addr);
                erc1155_instance.burn_batch(operator, ids.clone(), amounts);
            }
            self.env().emit_event(BurnBatch {
                accounts,
                owner: operator,
                token_ids: ids,
            });
        }
        #[ink(message)]
        pub fn safe_transfer_from(
            &mut self,
            from: AccountId,
            to: AccountId,
            token_id: TokenId,
            value: Balance,
            data: Vec<u8>,
        ) {
            #[cfg(not(test))]
            {
  let caller = self.env().caller();
            let caller_id = self.account_id_to_token_id(caller);
                let mut erc1155_instance: ContractRef =
                    ink_env::call::FromAccountId::from_account_id(self.contract_addr);
                assert!(
                    erc1155_instance.balance_of(to, token_id) == 0,
                    "5Degrees: already minted"
                );
                assert!(
                    erc1155_instance.balance_of(to, caller_id) > 0,
                    "5Degrees: receiver hasn't minted sender's NFT"
                );
                let _r = erc1155_instance.safe_transfer_from(from, to, token_id, value, data);
            }
            let total_balance = self._total_balance.get(&from).unwrap();
            self._total_balance.insert(&from, &(total_balance - value));
            let total_balance = self._total_balance.get(&to).unwrap();
            self._total_balance.insert(&to, &(total_balance + value));

            // Ok(())
        }

        #[ink(message)]
        pub fn safe_batch_transfer_from(
            &mut self,
            from: AccountId,
            to: AccountId,
            token_ids: Vec<TokenId>,
            values: Vec<Balance>,
            data: Vec<u8>,
        ) {
            assert!(
                token_ids.len() == values.len(),
                "5Degrees: length of ids and amounts mismatch",
            );
            let mut amount = 0;
            let transfers = token_ids.iter().zip(values.iter());
            for (&id, &v) in transfers.clone() {
                #[cfg(not(test))]
                {
                    let erc1155_instance: ContractRef =
                        ink_env::call::FromAccountId::from_account_id(self.contract_addr);
                    assert!(
                        erc1155_instance.balance_of(to, id) == 0,
                        "5Degrees: already minted"
                    );
                }
                amount += v;
            }

            #[cfg(not(test))]
            {
            let caller = self.env().caller();
            let caller_id = self.account_id_to_token_id(caller);
                let mut erc1155_instance: ContractRef =
                    ink_env::call::FromAccountId::from_account_id(self.contract_addr);
                assert!(
                    erc1155_instance.balance_of(to, caller_id) > 0,
                    "5Degrees: receiver hasn't minted sender's NFT"
                );
                let _r =
                    erc1155_instance.safe_batch_transfer_from(from, to, token_ids, values, data);
            }
            let total_balance = self._total_balance.get(&from).unwrap();
            self._total_balance.insert(&from, &(total_balance - amount));
            let total_balance = self._total_balance.get(&to).unwrap();
            self._total_balance.insert(&to, &(total_balance + amount));

            // Ok(())
        }
        fn account_id_to_token_id(&self, account: AccountId) -> TokenId {
            let _a = format!("{:?}", account);
            use scale::Decode;
            let aa = vec![0; 32];
            let _decoded = AccountId::decode(&mut &aa[..]).unwrap();
            0
        }
    }

    /// Unit tests in Rust are normally defined within such a `#[cfg(test)]`
    /// module and test functions are marked with a `#[test]` attribute.
    /// The below code is technically just normal Rust code.
    #[cfg(test)]
    mod tests {
        /// Imports all the definitions from the outer scope so we can use them here.
        use super::*;

        /// Imports `ink_lang` so we can use `#[ink::test]`.
        use ink_lang as ink;

        fn set_sender(sender: AccountId) {
            ink_env::test::set_caller::<Environment>(sender);
        }

        fn default_accounts() -> ink_env::test::DefaultAccounts<Environment> {
            ink_env::test::default_accounts::<Environment>()
        }

        fn alice() -> AccountId {
            default_accounts().alice
        }

        fn bob() -> AccountId {
            default_accounts().bob
        }

        fn charlie() -> AccountId {
            default_accounts().charlie
        }
        fn django() -> AccountId {
            default_accounts().django
        }

        fn eve() -> AccountId {
            default_accounts().eve
        }

        fn frank() -> AccountId {
            default_accounts().frank
        }
        fn init_contract() -> FiveDegrees {
            let name = Hash::from([0x99; 32]);
            let five = FiveDegrees::new(1, name);
            // five.balances.insert((alice(), 1), &10);
            // five.balances.insert((alice(), 2), &20);
            // five.balances.insert((bob(), 1), &10);

            five
        }

        #[ink::test]
        fn set_protocol_info() {
            let mut five = init_contract();
            five.set_protocol_info(String::from(""),String::from(""),String::from(""));
            assert_eq!(five.base_info(alice()), (String::from(""),String::from("")));
        }

        #[ink::test]
        fn metrics() {
            let five = init_contract();

            assert_eq!(five.metrics(alice()), (10, 20));
        }

        #[ink::test]
        fn set_pay_proxy() {
            let mut five = init_contract();
            five.set_pay_proxy(alice());
            assert_eq!(five.pay_proxy, alice());
        }

        #[ink::test]
        fn set_info() {
            let mut five = init_contract();
            five.set_info(String::from(""), String::from(""),String::from(""));
            assert_eq!(five.base_info(alice()), (String::from(""),String::from("")));
        }

        #[ink::test]
        fn increase_max_supply() {
            let mut five = init_contract();
            let owner = alice();
            let operator = bob();
            let another_operator = charlie();
            set_sender(owner);

            five.increase_max_supply(1);
        }
        #[ink::test]
        fn decrease_max_supply() {
            let mut five = init_contract();
            let owner = alice();
            let operator = bob();
            let another_operator = charlie();
            set_sender(owner);

            five.decrease_max_supply(1);
        }

        #[ink::test]
        fn minting_tokens_works() {
            let mut five = init_contract();
            set_sender(alice());
            five.mint(alice());
            // assert!(.is_ok());
            // assert_eq!(five.balance_of(alice(), 1), 123);
        }
        #[ink::test]
        fn mint_by_origin_tokens_works() {
            let mut five = init_contract();
            set_sender(alice());
            five.mint_by_origin(alice(), bob());
            // assert!(.is_ok());
            // assert_eq!(five.balance_of(alice(), 1), 123);
        }

        #[ink::test]
        fn mint_batch() {
            let mut five = init_contract();

            five.mint_batch(vec![alice(), bob()]);
        }
        #[ink::test]
        fn mint_batch_by_origin() {
            let mut five = init_contract();

            five.mint_batch(vec![alice(), bob()]);
        }

        #[ink::test]
        fn burning_tokens_works() {
            let mut five = init_contract();
            set_sender(alice());
            five.burn(alice());
            // assert!(.is_ok());
            // assert_eq!(five.balance_of(alice(), 1), 123);
        }
        #[ink::test]
        fn burn_by_origin_tokens_works() {
            let mut five = init_contract();
            set_sender(alice());
            five.burn_by_origin(alice(), bob());
            // assert!(.is_ok());
            // assert_eq!(five.balance_of(alice(), 1), 123);
        }

        #[ink::test]
        fn burn_batch() {
            let mut five = init_contract();
            five.burn_batch(vec![alice(), bob()]);
        }
        #[ink::test]
        fn burn_batch_by_origin() {
            let mut five = init_contract();
            five.burn_batch_by_origin(alice(), vec![alice(), bob()]);
        }

        #[ink::test]
        fn sending_too_many_tokens_fails() {
            let mut five = init_contract();
            five.safe_transfer_from(alice(), bob(), 1, 99, vec![]);
        }

        #[ink::test]
        fn sending_tokens_to_zero_address_fails() {
            let burn: AccountId = [0; 32].into();

            let mut five = init_contract();
            five.safe_transfer_from(alice(), burn, 1, 10, vec![]);
        }

        #[ink::test]
        fn can_send_batch_tokens() {
            let mut five = init_contract();
            five.safe_batch_transfer_from(alice(), bob(), vec![1, 2], vec![5, 10], vec![]);
        }

        #[ink::test]
        fn rejects_batch_if_lengths_dont_match() {
            let mut five = init_contract();
            five.safe_batch_transfer_from(alice(), bob(), vec![1, 2, 3], vec![5], vec![]);
        }

        #[ink::test]
        fn batch_transfers_fail_if_len_is_zero() {
            let mut five = init_contract();
            five.safe_batch_transfer_from(alice(), bob(), vec![], vec![], vec![]);
        }
    }
}
