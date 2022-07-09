//! #  Hex space social graph
//!
//! Hex spaceis a Web3 social network protocol deployed on multi-chain.
//! It aims to enable content creator to obtain his connections among communities and friends,
//!  and form a complete combinable, users-owned decentralized social network.
//!
//! ## Warning
//!
//! This contract is an *example*. It is neither audited nor endorsed for production use.
//! Do **not** rely on it to keep anything of value secure.
//!
//! ## Overview
//!
//! Web2.0 social networks all read data from their centralized databases,
//! which is lack of portability and controllability.
//! Your profile and social relationship will be stored in a specific network and owned by the operator.
//! This can lead to a zero-sum game in which different companies have to fight for their user’s data instead of good user experience.
//! However, the core mission of Web3.0 is to give the data ownership back to Web2.0 users,
//! which is what HexSpace is committed to do, allowing users to take control of their social data.
//! To make the protocol easy to use, permissionless, and composable,
//! we decided to build it under the framework of the existing ERC-1155 protocol.
//! Being compatible with the ERC-1155 standard, it can be easily implanted into any protocol or business of Web3.0 that supports ERC-1155,
//! which brings more possibilities to the composability of the current DEFI.
//! The application of the integrated protocol is able to quickly support this protocol as long as it supports the ERC-1155 protocol.
//! The Hex space protocol is completely open-source, and the protocol needs to be built by a large number of developers.
//! Now you don’t have to struggle with the access of user relationships anymore.
//! Just focus on developing your product better through the permissionless user relationship network.
//! We will still be committed to achieving more DApp integrations and making Web3.0 happen everywhere.
//!
//!
//! ## Error Handling
//!
//! Any error or invariant violation triggers a panic and therefore
//! rolls back the transaction.
//!
//! ## Interface
//!
//! The interface is modelled after the 5degrees protocol. However, there
//! are subtle variations from the interface.
//!
//!
//! ### Profile
//!
//! Profile NFT is the main object in HexSpace protocol. You can take control of all the contents of your NFT.
//! Every single address can have its own profile, and each address can have multiple Profile NFTs apart from the address itself.
//! Profile NFT follows the metadata format of EIP-1155.
//! You can easily set your avatar, nickname, Twitter account, Email address, profiles, and so on.
//! Any format is supported for your avatar. It can simply be a picture link or an NFT.
//!
//! ### Follow
//!
//! The "Follow" feature of HexSpace is essentially different from that feature of Web2.0 social products.
//! In HexSpace protocol, when a user follows a creator, he can obtain the creator’s personal NFT at the same time.
//! Different creators and communities can encode it and even give it additional value.
//! The ID of Follow NFT is serialized to the address of the creator (the one being followed), which ensures the uniqueness of the NFT ID.
//! Because the HexSpace follows the EIP-1155 protocol and simplifies the relationship network,
//! only a simple query - ‘balance_of()’ - is needed in order to know whether the two addresses have formed a relationship.
//!

#![cfg_attr(not(feature = "std"), no_std)]

use ink_lang as ink;
/// Hex space is a Web3 social network protocol . It aims to ena
/// and form a complete combinable, users-owned decentralized social network.
#[ink::contract]
mod hex_space {
    use erc1155::{
        erc1155::Burn, erc1155::BurnBatch, erc1155::Mint, erc1155::MintBatch, erc1155::Uri, TokenId,
    };
    use ink_lang::codegen::EmitEvent;

    use ink_env::format;
    use ink_prelude::string::String;
    use ink_prelude::vec::Vec;
    use ink_storage::{
        traits::{PackedLayout, SpreadAllocate, SpreadLayout},
        Mapping,
    };

    /// A struct containing profile data.
    ///
    /// name The nickname of this profile.
    /// image The avatar of this profile.
    /// max_supply Follower limitation of this profile NFT.
    /// properties Extension data of this profile NFT,eg:twitter,...
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

    /// A struct containing profile json.
    ///
    /// name The nickname of this profile.
    /// image The avatar of this profile.
    /// max_supply Follower limitation of this profile NFT.
    /// tokenSupply Follower count of this profile NFT.
    /// totalBalance Following count of this profile NFT.
    /// properties Extension data of this profile NFT,eg:twitter,...
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

    #[ink(storage)]
    #[derive(SpreadAllocate)]
    pub struct HexSpace {
        /// Mapping from owner to profile info.
        _uri: Mapping<AccountId, TokenURIInfo>,
        /// Mapping from owner to profile followers.
        _token_supply: Mapping<AccountId, Balance>,
        /// Mapping from owner to profile followings.
        _total_balance: Mapping<AccountId, Balance>,
        /// Pay proxy.
        pay_proxy: AccountId,
        /// Erc1155  instance contract address.
        contract_addr: AccountId,
        ///  Mapping from owner to token ids for test.
        test_balances: Mapping<(AccountId, TokenId), Balance>,
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

    impl HexSpace {
        /// Constructor that initializes the `u32` value to the given `version`.
        /// the `Hash` value to the given `code_hash`.
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
                    let total_balance = Self::env().balance();
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

        /// Sets the protocol info of the contract to the given name, image, properties.
        /// # Fields
        /// name: name of Profile NFT
        /// image: avatar of Profile NFT
        /// properties: extension data of Profile NFT
        #[ink(message)]
        pub fn set_protocol_info(&mut self, name: String, image: String, properties: String) {
            let token_id = self.env().account_id();
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

        /// Query Profile NFT Metadata.
        /// tokenId: Profile NFT ID
        /// tokenId: Use the t address uint256, that is, hexadecimal to 10 interpretations.
        /// eg: uint256(uint160("$(address)"))
        /// Return metadata format as below:
        /// the JSON metadata to use base64 encode.
        /// name: name of Profile NFT
        /// image: avatar of Profile NFT
        /// maxSupply: Follower limitation
        /// tokenSupply:followers of Profile NFT
        /// totalBalance:followings of Profile NFT
        /// properties: extension data of Profile NFT
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

        /// Return  encode packed abi string of the given items.
        /// # Fields
        /// items: items of profile info
        fn abi_string_encode_packed(&self, items: &String) -> String {
            let hexed = items.bytes().fold(String::new(), |mut acc, i| {
                acc.push_str(format!("{:02x}", i).as_str());
                acc
            });
            hexed
        }

        /// Return  base674 encode string of the given string.
        /// # Fields
        /// buf: buffer string
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
        /// Query base info of Profile NFT, return name and image.
        /// # Fields
        /// account: The given account.
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
        /// Query info of Profile NFT, return TokenURIInfo.
        /// # Fields
        /// account: The given account.
        #[ink(message)]
        pub fn info(&self, account: AccountId) -> TokenURIInfo {
            let info = self._uri.get(&account).unwrap_or(TokenURIInfo {
                name: String::new(),
                image: String::new(),
                max_supply: 2022,
                properties: String::new(),
            });
            info
        }
        /// Query Profile NFT followings and followers.
        /// # Fields
        /// account: which Profile NFT query
        /// # Returns
        /// tokenSupply: followers of Profile NFT
        /// totalBalance:followings of Profile NFT
        #[ink(message)]
        pub fn metrics(&self, account: AccountId) -> (u128, u128) {
            let token_supply = self._token_supply.get(&account).unwrap_or(0);
            let total_balance = self._total_balance.get(&account).unwrap_or(0);
            (token_supply, total_balance)
        }
        /// Set pay proxy of the given account Id.
        #[ink(message)]
        pub fn set_pay_proxy(&mut self, proxy: AccountId) {
            //onlyOwner
            self.pay_proxy = proxy;
        }
        /// Get pay proxy of the contract.
        #[ink(message)]
        pub fn pay_proxy(&self) -> AccountId {
            self.pay_proxy
        }
        /// Get pay proxy of the ERC1155 instance contract address.
        #[ink(message)]
        pub fn contract_address(&self) -> AccountId {
            self.contract_addr
        }
        /// Set you owner NFT info
        /// # Fields
        /// name:  name of Profile NFT
        /// image: avatar of Profile NFT
        /// properties:   other info of Profile NFT
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

        /// Set you owner NFT info
        /// # Fields
        /// account:  the given proxy account
        /// newMax:  followers new max supply of Profile NFT
        /// theMax:  followers the max supply of Profile NFT
        fn pay_proxy_call(&mut self, account: AccountId, new_max: TokenId, the_max: TokenId) {
            let (token, receiver, amount) = self.query_pay(account, new_max, the_max);
            if amount > 0 {
                if token == AccountId::default() {
                    let value = self.env().transferred_value();
                    assert!(value >= amount, "HexSpace: invalid msg.value");
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
        /// Query your Profile NFT's followers max supply
        /// newMax:  followers new max supply of Profile NFT
        /// theMax:  followers the max supply of Profile NFT
        fn query_pay(
            &self,
            account: AccountId,
            new_max: TokenId,
            _the_max: TokenId,
        ) -> (AccountId, AccountId, TokenId) {
            let (token, receiver, amount) = (account, account, new_max);
            (token, receiver, amount)
        }

        /// Call selector of the 'token' ERC20 address
        /// # Fields
        /// token: the address of the ERC20 token contract
        /// selector:   the interface method of the ERC20 token contract
        /// account:   the  'account' parameter of the  method of the ERC20 token contract
        /// receiver:   the  'receiver' parameter of the  method of the ERC20 token contract
        /// amount:   the 'amount' parameter of the  method of the ERC20 token contract
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
                    "token:{:?},selector:{:?},account:{:?},receiver:{:?},amount:{:?}",
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
        /// increase your Profile NFT's followers max supply
        /// newMax:  followers new max supply of Profile NFT
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
            assert!(the_max < new_max, "HexSpace: support increase only");
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
        /// decrease your Profile NFT's followers max supply
        /// # Fields
        /// newMax:  followers new max supply of Profile NFT
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
                "HexSpace: support increase only"
            );
            assert!(info.max_supply > new_max, "HexSpace: support increase only");

            info.max_supply = new_max;
            self._uri.insert(token_id, &info);
            let value = self.uri(token_id);
            self.env().emit_event(Uri {
                value,
                token_id: self.account_id_to_token_id(token_id),
            });
        }
        /// following which address
        /// # Fields
        /// account: followed address
        #[ink(message)]
        pub fn mint(&mut self, account: AccountId) {
            let operator = self.env().caller();
            self._internal_mint(operator, account);
        }
        /// following which address
        /// # Fields
        /// account: followed address
        #[ink(message)]
        pub fn mint_by_origin(&mut self, account: AccountId) {
            let operator = self.env().caller();
            #[cfg(not(test))]
            {
                assert!(self.env().caller_is_origin());
            }

            self._internal_mint(operator, account);
        }
        /// following which address by the operator
        /// # Fields
        /// operator: caller address
        /// account: followed address
        fn _internal_mint(&mut self, operator: AccountId, account: AccountId) {
            let token_id = self.account_id_to_token_id(account);
            assert!(operator != account, "HexSpace: cannot mint your own NFT");
            assert!(
                self.balance_of(operator, account) == 0,
                "HexSpace: already minted"
            );
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
                    "HexSpace: larger than max supply"
                );
            }
            #[cfg(not(test))]
            {
                use erc1155::ContractRef;
                let mut erc1155_instance: ContractRef =
                    ink_env::call::FromAccountId::from_account_id(self.contract_addr);
                let _r = erc1155_instance.mint_to(operator, token_id, 1);
                assert!(_r.is_ok(), "HexSpace: call erc1155 mint_to failed");
            }
            let total_balance = self._total_balance.get(&operator).unwrap_or(0);
            self._total_balance.insert(&operator, &(total_balance + 1));
            self._token_supply.insert(&account, &(token_supply + 1));
            self.env().emit_event(Mint {
                account,
                owner: operator,
                token_id,
            });
        }
        /// following of batch
        /// # Fields
        /// accounts:  followed address list
        #[ink(message)]
        pub fn mint_batch(&mut self, account: Vec<AccountId>) {
            let operator = self.env().caller();
            self._internal_mint_batch(operator, account);
        }
        /// following of batch by origin
        /// # Fields
        /// accounts:  followed address list
        #[ink(message)]
        pub fn mint_batch_by_origin(&mut self, accounts: Vec<AccountId>) {
            let operator = self.env().caller();
            #[cfg(not(test))]
            {
                assert!(self.env().caller_is_origin());
            }
            self._internal_mint_batch(operator, accounts);
        }

        /// following of batch  internal
        /// # Fields
        /// operator: caller address
        /// accounts:  followed address list
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
                if self.balance_of(operator, account) > 0 {
                    continue;
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
                let mut erc1155_instance: ContractRef =
                    ink_env::call::FromAccountId::from_account_id(self.contract_addr);
                let _r = erc1155_instance.mint_to_batch(operator, ids.clone(), amounts);
                assert!(_r.is_ok(), "HexSpace: call erc1155 mint_to_batch failed");
            }
            self.env().emit_event(MintBatch {
                accounts,
                owner: operator,
                token_ids: ids,
            });
        }
        /// unfollow which address
        /// # Fields
        /// account:  unfollowed address
        #[ink(message)]
        pub fn burn(&mut self, account: AccountId) {
            let operator = self.env().caller();
            self._internal_burn(operator, account);
        }
        /// unfollow which address by origin
        /// # Fields
        /// account:  unfollowed address
        #[ink(message)]
        pub fn burn_by_origin(&mut self, account: AccountId) {
            let operator = self.env().caller();
            #[cfg(not(test))]
            {
                assert!(self.env().caller_is_origin());
            }
            self._internal_burn(operator, account);
        }
        /// unfollow which address internal
        /// # Fields
        /// account:  unfollowed address
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
                    "HexSpace:  token not existed"
                );
                let _r = erc1155_instance.burn(operator, token_id, 1);
                assert!(_r.is_ok(), "HexSpace: call erc1155 burn failed");
            }
            let token_supply = self._token_supply.get(&account).unwrap_or(0);
            assert!(token_supply > 0, "HexSpace: Insufficient token_supply");
            self._token_supply.insert(&account, &(token_supply - 1));

            let total_balance = self._total_balance.get(&operator).unwrap_or(0);
            assert!(total_balance > 0, "HexSpace: Insufficient  Balance");
            self._total_balance.insert(&operator, &(total_balance - 1));
            self.env().emit_event(Burn {
                account,
                owner: operator,
                token_id,
            });
        }
        /// unfollow of batch
        /// # Fields
        /// accounts: unfollowed address list
        #[ink(message)]
        pub fn burn_batch(&mut self, account: Vec<AccountId>) {
            let operator = self.env().caller();
            self._internal_burn_batch(operator, account);
        }
        /// unfollow of batch by origin
        /// # Fields
        /// accounts: unfollowed address list
        #[ink(message)]
        pub fn burn_batch_by_origin(&mut self, accounts: Vec<AccountId>) {
            let operator = self.env().caller();
            #[cfg(not(test))]
            {
                assert!(self.env().caller_is_origin());
            }
            self._internal_burn_batch(operator, accounts);
        }
        /// unfollow of batch internal
        /// # Fields
        /// accounts: unfollowed address list
        fn _internal_burn_batch(&mut self, operator: AccountId, accounts: Vec<AccountId>) {
            let mut ids = Vec::new();
            let mut amounts = Vec::new();
            for &account in &accounts {
                let token_id = self.account_id_to_token_id(account);
                if self.balance_of(operator, account) == 0 {
                    continue;
                }
                let token_supply = self._token_supply.get(&account).unwrap_or(0);
                assert!(token_supply > 0, "HexSpace: Insufficient token_supply");
                self._token_supply.insert(&account, &(token_supply - 1));

                let total_balance = self._total_balance.get(&operator).unwrap_or(0);
                assert!(total_balance > 0, "HexSpace: Insufficient  Balance");
                self._total_balance.insert(&operator, &(total_balance - 1));
                ids.push(token_id);
                amounts.push(1);
            }
            #[cfg(not(test))]
            {
                use erc1155::ContractRef;
                let mut erc1155_instance: ContractRef =
                    ink_env::call::FromAccountId::from_account_id(self.contract_addr);
                let _r = erc1155_instance.burn_batch(operator, ids.clone(), amounts);
                assert!(_r.is_ok(), "HexSpace: call erc1155 burn_batch failed");
            }
            self.env().emit_event(BurnBatch {
                accounts,
                owner: operator,
                token_ids: ids,
            });
        }

        /// Transfers `value` tokens on the behalf of `from` to the account `to`.
        ///
        /// This can be used to allow a contract to transfer tokens on ones behalf and/or
        /// to charge fees in sub-currencies, for example.
        ///
        /// On success a `TransferSingle` event is emitted.
        ///
        #[ink(message)]
        pub fn safe_transfer_from(
            &mut self,
            from: AccountId,
            to: AccountId,
            token_id: AccountId,
            value: Balance,
            data: Vec<u8>,
        ) {
            #[cfg(test)]
            {
                ink_env::debug_println!("token_id: {:?}, data: ({:?})", token_id, data);
            }
            #[cfg(not(test))]
            {
                let caller = self.env().caller();
                let caller_id = self.account_id_to_token_id(caller);
                let token_id = self.account_id_to_token_id(token_id);
                use erc1155::ContractRef;
                use erc1155::Erc1155;
                let mut erc1155_instance: ContractRef =
                    ink_env::call::FromAccountId::from_account_id(self.contract_addr);
                assert!(
                    erc1155_instance.balance_of(to, token_id) == 0,
                    "HexSpace: already minted"
                );
                assert!(
                    erc1155_instance.balance_of(to, caller_id) > 0,
                    "HexSpace: receiver hasn't minted sender's NFT"
                );
                let _r = erc1155_instance.safe_transfer_from(from, to, token_id, value, data);
                assert!(
                    _r.is_ok(),
                    "HexSpace: call erc1155 safe_transfer_from failed"
                );
            }
            let total_balance = self._total_balance.get(&from).unwrap_or(0);
            assert!(total_balance >= value, "HexSpace: Insufficient Balance");
            self._total_balance.insert(&from, &(total_balance - value));
            let total_balance = self._total_balance.get(&to).unwrap_or(0);
            self._total_balance.insert(&to, &(total_balance + value));
        }
        /// Batch transfers `values` token ids on the behalf of `from` to the account `to`.
        ///
        /// This can be used to allow a contract to transfer tokens on ones behalf and/or
        /// to charge fees in sub-currencies, for example.
        ///
        /// On success a `TransferSingle` event is emitted.
        ///
        #[ink(message)]
        pub fn safe_batch_transfer_from(
            &mut self,
            from: AccountId,
            to: AccountId,
            token_ids: Vec<AccountId>,
            values: Vec<Balance>,
            data: Vec<u8>,
        ) {
            #[cfg(test)]
            {
                ink_env::debug_println!("to: {:?} data{:?}", to, data);
            }
            assert!(
                token_ids.len() == values.len(),
                "HexSpace: length of ids and amounts mismatch",
            );
            let mut amount = 0;
            let transfers = token_ids.iter().zip(values.iter());
            for (&id, &v) in transfers.clone() {
                #[cfg(test)]
                {
                    ink_env::debug_println!("id:{:?},v: ({:?})", id, v);
                }
                #[cfg(not(test))]
                {
                    let id = self.account_id_to_token_id(id);
                    use erc1155::ContractRef;
                    use erc1155::Erc1155;
                    let erc1155_instance: ContractRef =
                        ink_env::call::FromAccountId::from_account_id(self.contract_addr);
                    assert!(
                        erc1155_instance.balance_of(to, id) == 0,
                        "HexSpace: already minted"
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
                    "HexSpace: receiver hasn't minted sender's NFT"
                );
                let token_ids: Vec<TokenId> = token_ids
                    .into_iter()
                    .map(|id| self.account_id_to_token_id(id))
                    .collect();
                let _r =
                    erc1155_instance.safe_batch_transfer_from(from, to, token_ids, values, data);
                assert!(
                    _r.is_ok(),
                    "HexSpace: call erc1155 safe_batch_transfer_from failed"
                );
            }
            let total_balance = self._total_balance.get(&from).unwrap_or(0);
            assert!(total_balance >= amount, "HexSpace: Insufficient Balance");
            self._total_balance.insert(&from, &(total_balance - amount));
            let total_balance = self._total_balance.get(&to).unwrap_or(0);
            self._total_balance.insert(&to, &(total_balance + amount));
        }
        /// Find out follow or not through the method `balanc_of`, it represents being followed or following if return value is larger than 0.
        /// # Field
        /// account is the address trigger the follow action, token_id is the address of the account being followed.
        /// eg: ("$(address)")) or hexadecimal to 10 interpretations.
        /// Query if is being followed：
        /// Like if A is being followed by B -> balance_of(B,A)
        /// Query if is following：
        /// Like if A is following B -> balance_of(A,B)
        #[ink(message)]
        pub fn balance_of(&self, owner: AccountId, token_id: AccountId) -> Balance {
            #[cfg(test)]
            {
                ink_env::debug_println!("owner:{:?},token_id:{:?}", owner, token_id);
                let token_id = self.account_id_to_token_id(token_id);
                self.test_balances.get(&(owner, token_id)).unwrap_or(0)
            }
            #[cfg(not(test))]
            {
                let token_id = self.account_id_to_token_id(token_id);
                use erc1155::ContractRef;
                use erc1155::Erc1155;
                let erc1155_instance: ContractRef =
                    ink_env::call::FromAccountId::from_account_id(self.contract_addr);
                erc1155_instance.balance_of(owner, token_id)
            }
        }

        /// Find out follow or not through the method `balance_of_batch`, it represents being followed or following if return values is larger than 0.
        /// # Field
        /// `owners` is the addresses trigger the follow action,` token_ids` is the addresses of the accounts being followed.
        /// eg: ("$(address)")) or hexadecimal to 10 interpretations.
        /// Query if is being followed：
        /// Like if A is being followed by B -> balance_of_batch([B],[A])
        /// Query if is following：
        /// Like if A is following B -> balance_of_batch([A],[B])
        #[ink(message)]
        pub fn balance_of_batch(
            &self,
            owners: Vec<AccountId>,
            token_ids: Vec<AccountId>,
        ) -> Vec<Balance> {
            #[cfg(test)]
            {
                ink_env::debug_println!("owner: {:?},token_id:{:?}", owners, token_ids);
                vec![Balance::default()]
            }
            #[cfg(not(test))]
            {
                let mut output = Vec::new();
                for &t in &token_ids {
                    let token_id = self.account_id_to_token_id(t);
                    output.push(token_id);
                }

                use erc1155::ContractRef;
                use erc1155::Erc1155;
                let erc1155_instance: ContractRef =
                    ink_env::call::FromAccountId::from_account_id(self.contract_addr);
                erc1155_instance.balance_of_batch(owners, output)
            }
        }
        /// Convert the address of account to token id  .
        /// # Field
        /// `account` is the address of the given account
        /// Return is the addresses of the accounts being converted.
        fn account_id_to_token_id(&self, account: AccountId) -> TokenId {
            let aa: &[u8; 32] = account.as_ref();
            let ans = aa[..15]
                .iter()
                .map(|x| *x as u128)
                .reduce(|a, v| (a << 8) | v)
                .unwrap();
            #[cfg(test)]
            {
                ink_env::debug_println!("account:{:?},ans:{:?}", account, ans);
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
        use ink_env::Clear;
        use ink_lang as ink;

        type Event = <erc1155::Contract as ::ink_lang::reflect::ContractEventBase>::Type;

        fn assert_uri_event(
            event: &ink_env::test::EmittedEvent,
            expected_value: ink_prelude::string::String,
            expected_token_id: TokenId,
        ) {
            let decoded_event = <Event as scale::Decode>::decode(&mut &event.data[..])
                .expect("encountered invalid contract event data buffer");
            if let Event::Uri(Uri { value, token_id }) = decoded_event {
                assert_eq!(value, expected_value, "encountered invalid Uri.value");
                assert_eq!(
                    token_id, expected_token_id,
                    "encountered invalid Uri.token_id"
                );
            } else {
                panic!("encountered unexpected event kind: expected a Uri event")
            }
            let expected_topics = vec![
                encoded_into_hash(&PrefixedValue {
                    value: b"Contract::Uri",
                    prefix: b"",
                }),
                encoded_into_hash(&PrefixedValue {
                    prefix: b"Contract::Uri::token_id",
                    value: &expected_token_id,
                }),
            ];

            let topics = event.topics.clone();
            for (n, (actual_topic, expected_topic)) in
                topics.iter().zip(expected_topics).enumerate()
            {
                let mut topic_hash = Hash::clear();
                let len = actual_topic.len();
                topic_hash.as_mut()[0..len].copy_from_slice(&actual_topic[0..len]);

                assert_eq!(
                    topic_hash, expected_topic,
                    "encountered invalid topic at {}",
                    n
                );
            }
        }

        fn assert_mint_event(
            event: &ink_env::test::EmittedEvent,
            expected_account: AccountId,
            expected_owner: AccountId,
            expected_token_id: TokenId,
        ) {
            let decoded_event = <Event as scale::Decode>::decode(&mut &event.data[..])
                .expect("encountered invalid contract event data buffer");
            if let Event::Mint(Mint {
                account,
                owner,
                token_id,
            }) = decoded_event
            {
                assert_eq!(
                    account, expected_account,
                    "encountered invalid Mint.account"
                );
                assert_eq!(owner, expected_owner, "encountered invalid Mint.owner");
                assert_eq!(
                    token_id, expected_token_id,
                    "encountered invalid Mint.token_id"
                );
            } else {
                panic!("encountered unexpected event kind: expected a Mint event")
            }
            let expected_topics = vec![
                encoded_into_hash(&PrefixedValue {
                    value: b"Contract::Mint",
                    prefix: b"",
                }),
                encoded_into_hash(&PrefixedValue {
                    prefix: b"Contract::Mint::account",
                    value: &expected_account,
                }),
                encoded_into_hash(&PrefixedValue {
                    prefix: b"Contract::Mint::owner",
                    value: &expected_owner,
                }),
                encoded_into_hash(&PrefixedValue {
                    prefix: b"Contract::Mint::token_id",
                    value: &expected_token_id,
                }),
            ];

            let topics = event.topics.clone();
            for (n, (actual_topic, expected_topic)) in
                topics.iter().zip(expected_topics).enumerate()
            {
                let mut topic_hash = Hash::clear();
                let len = actual_topic.len();
                topic_hash.as_mut()[0..len].copy_from_slice(&actual_topic[0..len]);

                assert_eq!(
                    topic_hash, expected_topic,
                    "encountered invalid topic at {}",
                    n
                );
            }
        }

        fn assert_mint_batch_event(
            event: &ink_env::test::EmittedEvent,
            expected_accounts: Vec<AccountId>,
            expected_owner: AccountId,
            expected_token_ids: Vec<TokenId>,
        ) {
            let decoded_event = <Event as scale::Decode>::decode(&mut &event.data[..])
                .expect("encountered invalid contract event data buffer");
            if let Event::MintBatch(MintBatch {
                accounts,
                owner,
                token_ids,
            }) = decoded_event
            {
                assert_eq!(
                    accounts, expected_accounts,
                    "encountered invalid MintBatch.accounts"
                );
                assert_eq!(owner, expected_owner, "encountered invalid MintBatch.owner");
                assert_eq!(
                    token_ids, expected_token_ids,
                    "encountered invalid MintBatch.token_ids"
                );
            } else {
                panic!("encountered unexpected event kind: expected a MintBatch event")
            }
            let expected_topics = vec![
                encoded_into_hash(&PrefixedValue {
                    value: b"Contract::MintBatch",
                    prefix: b"",
                }),
                encoded_into_hash(&PrefixedValue {
                    prefix: b"Contract::MintBatch::accounts",
                    value: &expected_accounts,
                }),
                encoded_into_hash(&PrefixedValue {
                    prefix: b"Contract::MintBatch::owner",
                    value: &expected_owner,
                }),
                encoded_into_hash(&PrefixedValue {
                    prefix: b"Contract::MintBatch::token_ids",
                    value: &expected_token_ids,
                }),
            ];

            let topics = event.topics.clone();
            for (n, (actual_topic, expected_topic)) in
                topics.iter().zip(expected_topics).enumerate()
            {
                let mut topic_hash = Hash::clear();
                let len = actual_topic.len();
                topic_hash.as_mut()[0..len].copy_from_slice(&actual_topic[0..len]);

                assert_eq!(
                    topic_hash, expected_topic,
                    "encountered invalid topic at {}",
                    n
                );
            }
        }

        fn assert_burn_event(
            event: &ink_env::test::EmittedEvent,
            expected_account: AccountId,
            expected_owner: AccountId,
            expected_token_id: TokenId,
        ) {
            let decoded_event = <Event as scale::Decode>::decode(&mut &event.data[..])
                .expect("encountered invalid contract event data buffer");
            if let Event::Burn(Burn {
                account,
                owner,
                token_id,
            }) = decoded_event
            {
                assert_eq!(
                    account, expected_account,
                    "encountered invalid Burn.account"
                );
                assert_eq!(owner, expected_owner, "encountered invalid Burn.owner");
                assert_eq!(
                    token_id, expected_token_id,
                    "encountered invalid Burn.token_id"
                );
            } else {
                panic!("encountered unexpected event kind: expected a Burn event")
            }
            let expected_topics = vec![
                encoded_into_hash(&PrefixedValue {
                    value: b"Contract::Burn",
                    prefix: b"",
                }),
                encoded_into_hash(&PrefixedValue {
                    prefix: b"Contract::Burn::account",
                    value: &expected_account,
                }),
                encoded_into_hash(&PrefixedValue {
                    prefix: b"Contract::Burn::owner",
                    value: &expected_owner,
                }),
                encoded_into_hash(&PrefixedValue {
                    prefix: b"Contract::Burn::token_id",
                    value: &expected_token_id,
                }),
            ];

            let topics = event.topics.clone();
            for (n, (actual_topic, expected_topic)) in
                topics.iter().zip(expected_topics).enumerate()
            {
                let mut topic_hash = Hash::clear();
                let len = actual_topic.len();
                topic_hash.as_mut()[0..len].copy_from_slice(&actual_topic[0..len]);

                assert_eq!(
                    topic_hash, expected_topic,
                    "encountered invalid topic at {}",
                    n
                );
            }
        }

        fn assert_burn_batch_event(
            event: &ink_env::test::EmittedEvent,
            expected_accounts: Vec<AccountId>,
            expected_owner: AccountId,
            expected_token_ids: Vec<TokenId>,
        ) {
            let decoded_event = <Event as scale::Decode>::decode(&mut &event.data[..])
                .expect("encountered invalid contract event data buffer");
            if let Event::BurnBatch(BurnBatch {
                accounts,
                owner,
                token_ids,
            }) = decoded_event
            {
                assert_eq!(
                    accounts, expected_accounts,
                    "encountered invalid BurnBatch.accounts"
                );

                assert_eq!(owner, expected_owner, "encountered invalid BurnBatch.owner");
                assert_eq!(
                    token_ids, expected_token_ids,
                    "encountered invalid BurnBatch.token_ids"
                );
            } else {
                panic!("encountered unexpected event kind: expected a BurnBatch event")
            }
            let expected_topics = vec![
                encoded_into_hash(&PrefixedValue {
                    value: b"Contract::BurnBatch",
                    prefix: b"",
                }),
                encoded_into_hash(&PrefixedValue {
                    prefix: b"Contract::BurnBatch::accounts",
                    value: &expected_accounts,
                }),
                encoded_into_hash(&PrefixedValue {
                    prefix: b"Contract::BurnBatch::owner",
                    value: &expected_owner,
                }),
                encoded_into_hash(&PrefixedValue {
                    prefix: b"Contract::BurnBatch::token_ids",
                    value: &expected_token_ids,
                }),
            ];

            let topics = event.topics.clone();
            for (n, (actual_topic, expected_topic)) in
                topics.iter().zip(expected_topics).enumerate()
            {
                let mut topic_hash = Hash::clear();
                let len = actual_topic.len();
                topic_hash.as_mut()[0..len].copy_from_slice(&actual_topic[0..len]);

                assert_eq!(
                    topic_hash, expected_topic,
                    "encountered invalid topic at {}",
                    n
                );
            }
        }

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
        fn init_contract() -> HexSpace {
            let name = Hash::from([0x99; 32]);
            let mut hex_space = HexSpace::new(1, name);
            let info = TokenURIInfo {
                name: String::new(),
                image: String::new(),
                max_supply: 2022,
                properties: String::new(),
            };
            for account in [alice(), bob(), charlie()] {
                hex_space._uri.insert(&account, &info);
                hex_space._total_balance.insert(&account, &15);
                hex_space._token_supply.insert(&account, &15);
            }

            hex_space
        }

        #[ink::test]
        fn set_protocol_info() {
            let mut hex_space = init_contract();
            hex_space.set_protocol_info(String::from(""), String::from(""), String::from(""));
            assert_eq!(
                hex_space.base_info(alice()),
                (String::from(""), String::from(""))
            );
            let emitted_events = ink_env::test::recorded_events().collect::<Vec<_>>();
            assert_eq!(1, emitted_events.len());
            let contract = ink_env::account_id::<ink_env::DefaultEnvironment>();
            let value = hex_space.uri(contract);
            let toke_id = hex_space.account_id_to_token_id(contract);

            assert_uri_event(&emitted_events[0], value, toke_id);
        }

        #[ink::test]
        fn metrics() {
            let hex_space = init_contract();

            assert_eq!(hex_space.metrics(alice()), (15, 15));
        }

        #[ink::test]
        fn set_pay_proxy() {
            let mut hex_space = init_contract();
            hex_space.set_pay_proxy(alice());
            assert_eq!(hex_space.pay_proxy, alice());
        }

        #[ink::test]
        fn set_info() {
            let mut hex_space = init_contract();
            let operator = alice();
            set_sender(operator);
            hex_space.set_info(String::from(""), String::from(""), String::from(""));
            assert_eq!(
                hex_space.base_info(alice()),
                (String::from(""), String::from(""))
            );
            let emitted_events = ink_env::test::recorded_events().collect::<Vec<_>>();
            assert_eq!(1, emitted_events.len());
            let value = hex_space.uri(operator);
            let toke_id = hex_space.account_id_to_token_id(operator);

            assert_uri_event(&emitted_events[0], value, toke_id);
        }

        #[ink::test]
        fn increase_max_supply() {
            let mut hex_space = init_contract();
            let operator = alice();
            set_sender(operator);

            hex_space.increase_max_supply(9000);
            let emitted_events = ink_env::test::recorded_events().collect::<Vec<_>>();
            assert_eq!(1, emitted_events.len());
            let value = hex_space.uri(operator);
            let toke_id = hex_space.account_id_to_token_id(operator);

            assert_uri_event(&emitted_events[0], value, toke_id);
        }
        #[ink::test]
        fn decrease_max_supply() {
            let mut hex_space = init_contract();
            let operator = alice();
            set_sender(operator);

            hex_space.decrease_max_supply(1000);
            let emitted_events = ink_env::test::recorded_events().collect::<Vec<_>>();
            assert_eq!(1, emitted_events.len());
            let value = hex_space.uri(operator);
            let toke_id = hex_space.account_id_to_token_id(operator);

            assert_uri_event(&emitted_events[0], value, toke_id);
        }

        #[ink::test]
        fn minting_tokens_works() {
            let mut hex_space = init_contract();
            let operator = alice();
            set_sender(operator);
            hex_space.mint(bob());
            let emitted_events = ink_env::test::recorded_events().collect::<Vec<_>>();
            assert_eq!(1, emitted_events.len());
            let toke_id = hex_space.account_id_to_token_id(bob());

            assert_mint_event(&emitted_events[0], bob(), operator, toke_id);
        }
        #[ink::test]
        fn mint_by_origin_tokens_works() {
            let mut hex_space = init_contract();
            let operator = alice();
            set_sender(operator);
            hex_space.mint_by_origin(bob());
            let emitted_events = ink_env::test::recorded_events().collect::<Vec<_>>();
            assert_eq!(1, emitted_events.len());
            let toke_id = hex_space.account_id_to_token_id(bob());

            assert_mint_event(&emitted_events[0], bob(), operator, toke_id);
        }

        #[ink::test]
        fn mint_batch() {
            let mut hex_space = init_contract();
            let operator = alice();
            set_sender(operator);
            let accounts_token_ids = vec![bob(), charlie()];
            hex_space.mint_batch(accounts_token_ids.clone());
            let emitted_events = ink_env::test::recorded_events().collect::<Vec<_>>();
            assert_eq!(1, emitted_events.len());
            let token_ids: Vec<TokenId> = accounts_token_ids
                .iter()
                .map(|&id| hex_space.account_id_to_token_id(id))
                .collect();
            assert_mint_batch_event(&emitted_events[0], accounts_token_ids, operator, token_ids);
        }
        #[ink::test]
        fn mint_batch_by_origin() {
            let mut hex_space = init_contract();
            let operator = alice();
            set_sender(operator);
            let accounts_token_ids = vec![bob(), charlie()];
            hex_space.mint_batch_by_origin(accounts_token_ids.clone());
            let emitted_events = ink_env::test::recorded_events().collect::<Vec<_>>();
            assert_eq!(1, emitted_events.len());
            let token_ids: Vec<TokenId> = accounts_token_ids
                .iter()
                .map(|&id| hex_space.account_id_to_token_id(id))
                .collect();
            assert_mint_batch_event(&emitted_events[0], accounts_token_ids, operator, token_ids);
        }

        #[ink::test]
        fn burning_tokens_works() {
            let mut hex_space = init_contract();
            let operator = alice();
            set_sender(operator);
            hex_space.burn(bob());
            let emitted_events = ink_env::test::recorded_events().collect::<Vec<_>>();
            assert_eq!(1, emitted_events.len());
            let toke_id = hex_space.account_id_to_token_id(bob());

            assert_burn_event(&emitted_events[0], bob(), operator, toke_id);
        }
        #[ink::test]
        fn burn_by_origin_tokens_works() {
            let mut hex_space = init_contract();
            let operator = alice();
            set_sender(operator);
            hex_space.burn_by_origin(bob());
            let emitted_events = ink_env::test::recorded_events().collect::<Vec<_>>();
            assert_eq!(1, emitted_events.len());
            let toke_id = hex_space.account_id_to_token_id(bob());

            assert_burn_event(&emitted_events[0], bob(), operator, toke_id);
        }

        #[ink::test]
        fn burn_batch() {
            let mut hex_space = init_contract();
            let operator = alice();
            set_sender(operator);
            let accounts_token_ids = vec![bob(), charlie()];
            let token_ids: Vec<TokenId> = accounts_token_ids
                .iter()
                .map(|&id| hex_space.account_id_to_token_id(id))
                .collect();
            hex_space.test_balances.insert((alice(), token_ids[0]), &1);
            hex_space.test_balances.insert((alice(), token_ids[1]), &1);
            hex_space.burn_batch(accounts_token_ids.clone());
            let emitted_events = ink_env::test::recorded_events().collect::<Vec<_>>();
            assert_eq!(1, emitted_events.len());
            assert_burn_batch_event(&emitted_events[0], accounts_token_ids, operator, token_ids);
        }
        #[ink::test]
        fn burn_batch_by_origin() {
            let mut hex_space = init_contract();
            let operator = alice();
            set_sender(operator);
            let accounts_token_ids = vec![bob(), charlie()];
            let token_ids: Vec<TokenId> = accounts_token_ids
                .iter()
                .map(|&id| hex_space.account_id_to_token_id(id))
                .collect();
            hex_space.test_balances.insert((alice(), token_ids[0]), &1);
            hex_space.test_balances.insert((alice(), token_ids[1]), &1);
            hex_space.burn_batch_by_origin(accounts_token_ids.clone());
            let emitted_events = ink_env::test::recorded_events().collect::<Vec<_>>();
            assert_eq!(1, emitted_events.len());

            assert_burn_batch_event(&emitted_events[0], accounts_token_ids, operator, token_ids);
        }

        #[ink::test]
        #[should_panic]
        fn sending_too_many_tokens_fails() {
            let mut hex_space = init_contract();
            hex_space.safe_transfer_from(bob(), charlie(), frank(), 99, vec![]);
        }

        #[ink::test]
        fn sending_tokens_to_zero_address_fails() {
            let burn: AccountId = [0; 32].into();

            let mut hex_space = init_contract();
            hex_space.safe_transfer_from(bob(), burn, frank(), 1, vec![]);
        }

        #[ink::test]
        fn account_id_to_token_id() {
            let burn: AccountId = [255; 32].into();
            let hex_space = init_contract();
            let token_id = hex_space.account_id_to_token_id(burn);
            assert_eq!(token_id, 1329227995784915872903807060280344575);
        }

        #[ink::test]
        fn uri() {
            let burn: AccountId = [255; 32].into();
            let mut hex_space = init_contract();
            let uri = hex_space.uri(burn);
            assert_eq!(uri, "646174613a6170706c69636174696f6e2f6a736f6e3b626173\
                            6536342c4d6a63325a5459784e6d51324e5449334d324579597a49334e6a6b325a4459784e6a6332\
                            4e5449334d324579597a49334e6d51324d5463344e544d334e5463774e7a4132597a63354d6a637a\
                            59544d794d7a417a4d6a4d794d6d4d794e7a63304e6d5932596a59314e6d55314d7a63314e7a41334\
                            d445a6a4e7a6b794e7a4e684d7a4179597a49334e7a51325a6a63304e6a4532597a51794e6a453259\
                            7a59784e6d55324d7a59314d6a637a59544d774d6a4179597a49334e7a41334d6a5a6d4e7a41324e54\
                            63794e7a51324f5459314e7a4d794e7a4e68");
        }
        #[ink::test]
        fn can_send_batch_tokens() {
            let mut hex_space = init_contract();
            hex_space.safe_batch_transfer_from(
                bob(),
                charlie(),
                vec![frank(), django()],
                vec![5, 10],
                vec![],
            );
        }

        #[ink::test]
        #[should_panic]
        fn rejects_batch_if_lengths_dont_match() {
            let mut hex_space = init_contract();
            hex_space.safe_batch_transfer_from(
                bob(),
                charlie(),
                vec![frank(), eve(), django()],
                vec![5],
                vec![],
            );
        }

        #[ink::test]
        fn batch_transfers_fail_if_len_is_zero() {
            let mut hex_space = init_contract();
            hex_space.safe_batch_transfer_from(bob(), charlie(), vec![], vec![], vec![]);
        }

        /// For calculating the event topic hash.
        struct PrefixedValue<'a, 'b, T> {
            pub prefix: &'a [u8],
            pub value: &'b T,
        }

        impl<X> scale::Encode for PrefixedValue<'_, '_, X>
        where
            X: scale::Encode,
        {
            #[inline]
            fn size_hint(&self) -> usize {
                self.prefix.size_hint() + self.value.size_hint()
            }

            #[inline]
            fn encode_to<T: scale::Output + ?Sized>(&self, dest: &mut T) {
                self.prefix.encode_to(dest);
                self.value.encode_to(dest);
            }
        }

        fn encoded_into_hash<T>(entity: &T) -> Hash
        where
            T: scale::Encode,
        {
            use ink_env::{
                hash::{Blake2x256, CryptoHash, HashOutput},
                Clear,
            };
            let mut result = Hash::clear();
            let len_result = result.as_ref().len();
            let encoded = entity.encode();
            let len_encoded = encoded.len();
            if len_encoded <= len_result {
                result.as_mut()[..len_encoded].copy_from_slice(&encoded);
                return result;
            }
            let mut hash_output = <<Blake2x256 as HashOutput>::Type as Default>::default();
            <Blake2x256 as CryptoHash>::hash(&encoded, &mut hash_output);
            let copy_len = core::cmp::min(hash_output.len(), len_result);
            result.as_mut()[0..copy_len].copy_from_slice(&hash_output[0..copy_len]);
            result
        }
    }
}
