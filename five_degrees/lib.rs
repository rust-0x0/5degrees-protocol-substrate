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
        erc1155::Burn, erc1155::BurnBatch, erc1155::Mint, erc1155::MintBatch, erc1155::Uri, TokenId,
    };

    use ink_env::format;
    use ink_prelude::string::String;
    use ink_prelude::vec;
    use ink_prelude::vec::Vec;
    use ink_storage::{
        traits::{PackedLayout, SpreadAllocate, SpreadLayout},
        Mapping,
    };

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
            #[cfg(test)]
            {
                ink_env::debug_println!("version at {:?} code_hash ({:?})", version, code_hash);
            }
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
                    use erc1155::ContractRef;
                    use erc1155::Erc1155;
                    // const CONTRACT_INIT_BALANCE: u128 = 1 * 1_000_000_000_000;
                    let total_balance = Self::env().balance();
                    // let version = self::length;
                    let salt = version.to_le_bytes();
                    let instance_params = ContractRef::new()
                        .endowment(total_balance / 4)
                        .code_hash(code_hash)
                        .salt_bytes(salt)
                        .params();
                    let init_result = ink_env::instantiate_contract(&instance_params);
                    let contract_addr =
                        init_result.expect("failed at instantiating the `Erc1155` contract");

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
            let value = self.uri(token_id);
            self.env().emit_event(Uri {
                value,
                token_id: self.account_id_to_token_id(self.env().account_id()),
            });
        }

        /// Simply returns the current value of our `bool`.
        fn uri(&mut self, token_id: AccountId) -> String {
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
            let followers = self._token_supply.get(&token_id).unwrap_or(0);
            let followings = self._total_balance.get(&token_id).unwrap_or(0);

            let json= format!("'name':{},'image':{},'maxSupply':{},'tokenSupply':{},'totalBalance':{} ,'properties':{}",info.name,info.image,info.max_supply,followers,followings,info.properties) ;
            let hexed = self.abi_string_encode_packed(&json);
            let ans = self.base64_encode(&hexed);
            let dt = format!("data:application/json;base64,{}", ans);
            self.abi_string_encode_packed(&dt)
        }
        fn abi_string_encode_packed(&self, items: &String) -> String {
            let hexed = items.bytes().fold(String::new(), |mut acc, i| {
                acc.push_str(format!("{:02x}", i).as_str());
                acc
            });
            hexed
        }

        fn base64_encode(&self, buf: &String) -> String {
            fn byte_to_char(key: u8) -> char {
                let b64_str: &str =
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

                b64_str.as_bytes()[key as usize] as _
            }
            fn a3_to_a4(a3: &[u8; 3]) -> [u8; 4] {
                let mut a4: [u8; 4] = [0u8; 4];
                a4[0] = a3[0] >> 2;
                a4[1] = (a3[0] << 6) >> 2 | a3[1] >> 4;
                a4[2] = (a3[1] << 4) >> 2 | a3[2] >> 6;
                a4[3] = (a3[2] << 2) >> 2;
                a4
            }

            let buf = buf.as_bytes();
            let num = buf.len();
            let mut result = String::new();
            result.reserve((num + 3) / 3 * 4);

            for item in buf.chunks(3) {
                if item.len() < 3 {
                    break;
                }
                let item = [item[0], item[1], item[2]];
                let a4 = a3_to_a4(&item);
                result.push_str(
                    a4.iter()
                        .map(|a| byte_to_char(*a))
                        .collect::<String>()
                        .as_str(),
                );
            }

            // 处理余下的1/2字节
            let mut item = [0, 0, 0];
            let mm = num % 3;
            if mm == 0 {
                return result;
            }
            if mm == 1 {
                item = [buf[num - 1], 0, 0];
            } else if mm == 2 {
                item = [buf[num - 2], buf[num - 1], 0];
            }
            let a4 = a3_to_a4(&item);
            result.push(byte_to_char(a4[0]));
            result.push(byte_to_char(a4[1]));
            let b2c = |b: u8| if b == 0 { '=' } else { byte_to_char(b) };
            result.push(b2c(a4[2]));
            result.push(b2c(a4[3]));
            result
        }
        #[ink(message)]
        pub fn base_info(&self, account: AccountId) -> (String, String) {
            let info = self._uri.get(&account).unwrap_or(TokenURIInfo {
                name: String::new(),
                image: String::new(),
                max_supply: 2022,
                properties: String::new(),
            });
            let name = info.name;
            let image = info.image;
            (name, image)
        }
        #[ink(message)]
        pub fn metrics(&self, account: AccountId) -> (u128, u128) {
            let token_supply = self._token_supply.get(&account).unwrap_or(0);
            let total_balance = self._total_balance.get(&account).unwrap_or(0);
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
            let value = self.uri(token_id);
            self.env().emit_event(Uri {
                value,
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
            #[cfg(test)]
            {
                ink_env::debug_println!(
                    "id at {:?} v ({:?}  {:?} v  {:?} v ({:?})",
                    token,
                    selector,
                    account,
                    receiver,
                    amount
                );
            }
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
            let value = self.uri(token_id);
            self.env().emit_event(Uri {
                value,
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
                self._token_supply.get(&token_id).unwrap_or(0) <= new_max,
                "5Degrees: support increase only"
            );
            assert!(info.max_supply > new_max, "5Degrees: support increase only");

            info.max_supply = new_max;
            self._uri.insert(token_id, &info);
            let value = self.uri(token_id);
            self.env().emit_event(Uri {
                value,
                token_id: self.account_id_to_token_id(token_id),
            });
        }
        #[ink(message)]
        pub fn mint(&mut self, account: AccountId) {
            let operator = self.env().caller();
            self._internal_mint(operator, account);
        }
        #[ink(message)]
        pub fn mint_by_origin(&mut self, operator: AccountId, account: AccountId) {
            // let operator = self.env().caller();
            //assert!(self.env().caller_is_origin());
            self._internal_mint(operator, account);
        }
        fn _internal_mint(&mut self, operator: AccountId, account: AccountId) {
            let token_id = self.account_id_to_token_id(account);
            assert!(operator != account, "5Degrees: cannot mint your own NFT");
            #[cfg(not(test))]
            {
                use erc1155::ContractRef;
                use erc1155::Erc1155;
                let erc1155_instance: ContractRef =
                    ink_env::call::FromAccountId::from_account_id(self.contract_addr);
                assert!(
                    erc1155_instance.balance_of(operator, token_id) == 0,
                    "5Degrees: already minted"
                );
            }

            let mut info = self._uri.get(&account).unwrap_or(TokenURIInfo {
                name: String::new(),
                image: String::new(),
                max_supply: 2022,
                properties: String::new(),
            });
            let token_supply = self._token_supply.get(&account).unwrap_or(0);
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
                use erc1155::ContractRef;
                use erc1155::Erc1155;
                let mut erc1155_instance: ContractRef =
                    ink_env::call::FromAccountId::from_account_id(self.contract_addr);
                let _r = erc1155_instance.mint_to(operator, token_id, 1);
            }
            let total_balance = self._total_balance.get(&operator).unwrap_or(0);
            self._total_balance.insert(&operator, &(total_balance + 1));
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
        pub fn mint_batch_by_origin(&mut self, operator: AccountId, accounts: Vec<AccountId>) {
            // let operator = self.env().caller();
            // assert!(self.env().caller_is_origin());
            self._internal_mint_batch(operator, accounts);
        }
        fn _internal_mint_batch(&mut self, operator: AccountId, accounts: Vec<AccountId>) {
            let mut ids = Vec::new();
            let mut amounts = Vec::new();
            for &account in &accounts {
                let token_id = self.account_id_to_token_id(account);
                let mut info = self._uri.get(&account).unwrap_or(TokenURIInfo {
                    name: String::new(),
                    image: String::new(),
                    max_supply: 2022,
                    properties: String::new(),
                });
                let token_supply = self._token_supply.get(&account).unwrap_or(0);
                if operator == account || token_supply + 1 > info.max_supply {
                    continue;
                }
                #[cfg(not(test))]
                {
                    use erc1155::ContractRef;
                    use erc1155::Erc1155;
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
                let total_balance = self._total_balance.get(&operator).unwrap_or(0);
                self._total_balance.insert(&operator, &(total_balance + 1));
                self._token_supply.insert(&account, &(token_supply + 1));
                ids.push(token_id);
                amounts.push(1);
            }
            #[cfg(not(test))]
            {
                use erc1155::ContractRef;
                use erc1155::Erc1155;
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
            self._internal_burn(operator, account);
        }
        #[ink(message)]
        pub fn burn_by_origin(&mut self, operator: AccountId, account: AccountId) {
            // let operator = self.env().caller();
            //assert!(self.env().caller_is_origin());
            self._internal_burn(operator, account);
        }
        fn _internal_burn(&mut self, operator: AccountId, account: AccountId) {
            let token_id = self.account_id_to_token_id(account);
            #[cfg(not(test))]
            {
                use erc1155::ContractRef;
                use erc1155::Erc1155;
                let mut erc1155_instance: ContractRef =
                    ink_env::call::FromAccountId::from_account_id(self.contract_addr);
                assert!(
                    erc1155_instance.balance_of(operator, token_id) > 0,
                    "5Degrees:  token not existed"
                );
                erc1155_instance.burn(operator, token_id, 1);
            }
            let token_supply = self._token_supply.get(&account).unwrap_or(0);
            assert!(token_supply > 0, "5Degrees: Insufficient token_supply");
            self._token_supply.insert(&account, &(token_supply - 1));

            let total_balance = self._total_balance.get(&operator).unwrap_or(0);
            assert!(total_balance > 0, "5Degrees: Insufficient  Balance");
            self._total_balance.insert(&operator, &(total_balance - 1));
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
                    use erc1155::ContractRef;
                    use erc1155::Erc1155;
                    let erc1155_instance: ContractRef =
                        ink_env::call::FromAccountId::from_account_id(self.contract_addr);
                    if erc1155_instance.balance_of(operator, token_id) == 0 {
                        continue;
                    }
                }
                let token_supply = self._token_supply.get(&account).unwrap_or(0);
                assert!(token_supply > 0, "5Degrees: Insufficient token_supply");
                self._token_supply.insert(&account, &(token_supply - 1));

                let total_balance = self._total_balance.get(&operator).unwrap_or(0);
                assert!(total_balance > 0, "5Degrees: Insufficient  Balance");
                self._total_balance.insert(&operator, &(total_balance - 1));
                ids.push(token_id);
                amounts.push(1);
            }
            #[cfg(not(test))]
            {
                use erc1155::ContractRef;
                use erc1155::Erc1155;
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
            #[cfg(test)]
            {
                ink_env::debug_println!("version at {:?} code_hash ({:?})", token_id, data);
            }
            #[cfg(not(test))]
            {
                let caller = self.env().caller();
                let caller_id = self.account_id_to_token_id(caller);
                use erc1155::ContractRef;
                use erc1155::Erc1155;
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
            let total_balance = self._total_balance.get(&from).unwrap_or(0);
            assert!(total_balance >= value, "5Degrees: Insufficient Balance");
            self._total_balance.insert(&from, &(total_balance - value));
            let total_balance = self._total_balance.get(&to).unwrap_or(0);
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
            #[cfg(test)]
            {
                ink_env::debug_println!("id at {:?} v ({:?})", to, data);
            }
            assert!(
                token_ids.len() == values.len(),
                "5Degrees: length of ids and amounts mismatch",
            );
            let mut amount = 0;
            let transfers = token_ids.iter().zip(values.iter());
            for (&id, &v) in transfers.clone() {
                #[cfg(test)]
                {
                    ink_env::debug_println!("id at {:?} v ({:?})", id, v);
                }
                #[cfg(not(test))]
                {
                    use erc1155::ContractRef;
                    use erc1155::Erc1155;
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
                use erc1155::ContractRef;
                use erc1155::Erc1155;
                let mut erc1155_instance: ContractRef =
                    ink_env::call::FromAccountId::from_account_id(self.contract_addr);
                assert!(
                    erc1155_instance.balance_of(to, caller_id) > 0,
                    "5Degrees: receiver hasn't minted sender's NFT"
                );
                let _r =
                    erc1155_instance.safe_batch_transfer_from(from, to, token_ids, values, data);
            }
            let total_balance = self._total_balance.get(&from).unwrap_or(0);
            assert!(total_balance >= amount, "5Degrees: Insufficient Balance");
            self._total_balance.insert(&from, &(total_balance - amount));
            let total_balance = self._total_balance.get(&to).unwrap_or(0);
            self._total_balance.insert(&to, &(total_balance + amount));

            // Ok(())
        }
        fn account_id_to_token_id(&self, account: AccountId) -> TokenId {
            let aa: &[u8; 32] = account.as_ref();
            let ans = aa[..15]
                .iter()
                .map(|x| *x as u128)
                .reduce(|a, v| (a << 8) | v)
                .unwrap();
            #[cfg(test)]
            {
                ink_env::debug_println!("{:?} account_id_to_token_id = {:?}", account, ans);
            }
            ans
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
        // fn django() -> AccountId {
        //     default_accounts().django
        // }

        // fn eve() -> AccountId {
        //     default_accounts().eve
        // }

        // fn frank() -> AccountId {
        //     default_accounts().frank
        // }
        fn init_contract() -> FiveDegrees {
            let name = Hash::from([0x99; 32]);
            let mut five = FiveDegrees::new(1, name);
            let info = TokenURIInfo {
                name: String::new(),
                image: String::new(),
                max_supply: 2022,
                properties: String::new(),
            };
            for account in [alice(), bob(), charlie()] {
                five._uri.insert(&account, &info);
                five._total_balance.insert(&account, &15);
                five._token_supply.insert(&account, &15);
            }

            five
        }

        #[ink::test]
        fn set_protocol_info() {
            let mut five = init_contract();
            five.set_protocol_info(String::from(""), String::from(""), String::from(""));
            assert_eq!(
                five.base_info(alice()),
                (String::from(""), String::from(""))
            );
        }

        #[ink::test]
        fn metrics() {
            let five = init_contract();

            assert_eq!(five.metrics(alice()), (15, 15));
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
            five.set_info(String::from(""), String::from(""), String::from(""));
            assert_eq!(
                five.base_info(alice()),
                (String::from(""), String::from(""))
            );
        }

        #[ink::test]
        fn increase_max_supply() {
            let mut five = init_contract();
            let owner = alice();
            // let operator = bob();
            // let another_operator = charlie();
            set_sender(owner);

            five.increase_max_supply(9000);
        }
        #[ink::test]
        fn decrease_max_supply() {
            let mut five = init_contract();
            let owner = alice();
            // let operator = bob();
            // let another_operator = charlie();
            set_sender(owner);

            five.decrease_max_supply(1000);
        }

        #[ink::test]
        fn minting_tokens_works() {
            let mut five = init_contract();
            set_sender(alice());
            five.mint(bob());
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
            set_sender(alice());
            five.mint_batch(vec![bob(), charlie()]);
        }
        #[ink::test]
        fn mint_batch_by_origin() {
            let mut five = init_contract();
            set_sender(alice());
            five.mint_batch_by_origin(alice(), vec![bob(), charlie()]);
        }

        #[ink::test]
        fn burning_tokens_works() {
            let mut five = init_contract();
            set_sender(alice());
            five.burn(bob());
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
            set_sender(alice());
            five.burn_batch(vec![alice(), charlie()]);
        }
        #[ink::test]
        fn burn_batch_by_origin() {
            let mut five = init_contract();
            five.burn_batch_by_origin(alice(), vec![bob(), charlie()]);
        }

        #[ink::test]
        #[should_panic]
        fn sending_too_many_tokens_fails() {
            let mut five = init_contract();
            five.safe_transfer_from(bob(), charlie(), 1, 99, vec![]);
        }

        #[ink::test]
        fn sending_tokens_to_zero_address_fails() {
            let burn: AccountId = [0; 32].into();

            let mut five = init_contract();
            five.safe_transfer_from(bob(), burn, 1, 1, vec![]);
        }

        #[ink::test]
        fn account_id_to_token_id() {
            let burn: AccountId = [255; 32].into();
            let five = init_contract();
            let token_id = five.account_id_to_token_id(burn);
            assert_eq!(token_id, 1329227995784915872903807060280344575);
        }

        #[ink::test]
        fn uri() {
            let burn: AccountId = [255; 32].into();
            let mut five = init_contract();
            let uri = five.uri(burn);
            assert_eq!(uri, "646174613a6170706c69636174696f6e2f6a736f6e3b6261736536342c4d6a63325a5459784e6d51324e5449334d324579597a49334e6a6b325a4459784e6a63324e5449334d324579597a49334e6d51324d5463344e544d334e5463774e7a4132597a63354d6a637a59544d794d7a417a4d6a4d794d6d4d794e7a63304e6d5932596a59314e6d55314d7a63314e7a41334d445a6a4e7a6b794e7a4e684d7a4179597a49334e7a51325a6a63304e6a4532597a51794e6a4532597a59784e6d55324d7a59314d6a637a59544d774d6a4179597a49334e7a41334d6a5a6d4e7a41324e5463794e7a51324f5459314e7a4d794e7a4e68");
        }
        #[ink::test]
        fn can_send_batch_tokens() {
            let mut five = init_contract();
            five.safe_batch_transfer_from(bob(), charlie(), vec![1, 2], vec![5, 10], vec![]);
        }

        #[ink::test]
        #[should_panic]
        fn rejects_batch_if_lengths_dont_match() {
            let mut five = init_contract();
            five.safe_batch_transfer_from(bob(), charlie(), vec![1, 2, 3], vec![5], vec![]);
        }

        #[ink::test]
        fn batch_transfers_fail_if_len_is_zero() {
            let mut five = init_contract();
            five.safe_batch_transfer_from(bob(), charlie(), vec![], vec![], vec![]);
        }
    }
}
