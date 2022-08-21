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

use ink_prelude::vec::Vec;

// This is the return value that we expect if a smart contract supports receiving ERC-1155
// tokens.
//
// It is calculated with
// `bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)"))`, and corresponds
// to 0xf23a6e61.
#[cfg_attr(test, allow(dead_code))]
const ON_ERC_1155_RECEIVED_SELECTOR: [u8; 4] = [0xF2, 0x3A, 0x6E, 0x61];

// This is the return value that we expect if a smart contract supports batch receiving ERC-1155
// tokens.
//
// It is calculated with
// `bytes4(keccak256("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)"))`, and
// corresponds to 0xbc197c81.
const _ON_ERC_1155_BATCH_RECEIVED_SELECTOR: [u8; 4] = [0xBC, 0x19, 0x7C, 0x81];

/// A type representing the unique IDs of tokens managed by this contract.
pub type TokenId = u128;

type Balance = <ink_env::DefaultEnvironment as ink_env::Environment>::Balance;

use crate::hex_space::Error;
// The ERC-1155 result types.
pub type Result<T> = core::result::Result<T, Error>;

/// Evaluate `$x:expr` and if not true return `Err($y:expr)`.
///
/// Used as `ensure!(expression_to_ensure, expression_to_return_on_false)`.
macro_rules! ensure {
    ( $condition:expr, $error:expr $(,)? ) => {{
        if !$condition {
            return ::core::result::Result::Err(::core::convert::Into::into($error));
        }
    }};
}

/// The interface for an ERC-1155 compliant contract.
///
/// The interface is defined here: <https://eips.ethereum.org/EIPS/eip-1155>.
///
/// The goal of ERC-1155 is to allow a single contract to manage a variety of assets.
/// These assets can be fungible, non-fungible, or a combination.
///
/// By tracking multiple assets the ERC-1155 standard is able to support batch transfers, which
/// make it easy to transfer a mix of multiple tokens at once.
#[ink::trait_definition]
pub trait Erc1155 {
    /// Transfer a `value` amount of `token_id` tokens to the `to` account from the `from`
    /// account.
    ///
    /// Note that the call does not have to originate from the `from` account, and may originate
    /// from any account which is approved to transfer `from`'s tokens.
    #[ink(message)]
    fn safe_transfer_from(
        &mut self,
        from: AccountId,
        to: AccountId,
        token_id: TokenId,
        value: Balance,
        data: Vec<u8>,
    ) -> Result<()>;

    /// Perform a batch transfer of `token_ids` to the `to` account from the `from` account.
    ///
    /// The number of `values` specified to be transferred must match the number of `token_ids`,
    /// otherwise this call will revert.
    ///
    /// Note that the call does not have to originate from the `from` account, and may originate
    /// from any account which is approved to transfer `from`'s tokens.
    #[ink(message)]
    fn safe_batch_transfer_from(
        &mut self,
        from: AccountId,
        to: AccountId,
        token_ids: Vec<TokenId>,
        values: Vec<Balance>,
        data: Vec<u8>,
    ) -> Result<()>;

    /// Query the balance of a specific token for the provided account.
    #[ink(message)]
    fn balance_of(&self, owner: AccountId, token_id: TokenId) -> Balance;

    /// Query the balances for a set of tokens for a set of accounts.
    ///
    /// E.g use this call if you want to query what Alice and Bob's balances are for Tokens ID 1 and
    /// ID 2.
    ///
    /// This will return all the balances for a given owner before moving on to the next owner. In
    /// the example above this means that the return value should look like:
    ///
    /// [Alice Balance of Token ID 1, Alice Balance of Token ID 2, Bob Balance of Token ID 1, Bob Balance of Token ID 2]
    #[ink(message)]
    fn balance_of_batch(&self, owners: Vec<AccountId>, token_ids: Vec<TokenId>) -> Vec<Balance>;

    /// Enable or disable a third party, known as an `operator`, to control all tokens on behalf of
    /// the caller.
    #[ink(message)]
    fn set_approval_for_all(&mut self, operator: AccountId, approved: bool) -> Result<()>;

    /// Query if the given `operator` is allowed to control all of `owner`'s tokens.
    #[ink(message)]
    fn is_approved_for_all(&self, owner: AccountId, operator: AccountId) -> bool;
}

/// The interface for an ERC-1155 Token Receiver contract.
///
/// The interface is defined here: <https://eips.ethereum.org/EIPS/eip-1155>.
///
/// Smart contracts which want to accept token transfers must implement this interface. By default
/// if a contract does not support this interface any transactions originating from an ERC-1155
/// compliant contract which attempt to transfer tokens directly to the contract's address must be
/// reverted.
#[ink::trait_definition]
pub trait Erc1155TokenReceiver {
    /// Handle the receipt of a single ERC-1155 token.
    ///
    /// This should be called by a compliant ERC-1155 contract if the intended recipient is a smart
    /// contract.
    ///
    /// If the smart contract implementing this interface accepts token transfers then it must
    /// return `ON_ERC_1155_RECEIVED_SELECTOR` from this function. To reject a transfer it must revert.
    ///
    /// Any callers must revert if they receive anything other than `ON_ERC_1155_RECEIVED_SELECTOR` as a return
    /// value.
    #[ink(message, selector = 0xF23A6E61)]
    fn on_received(
        &mut self,
        operator: AccountId,
        from: AccountId,
        token_id: TokenId,
        value: Balance,
        data: Vec<u8>,
    ) -> Vec<u8>;

    /// Handle the receipt of multiple ERC-1155 tokens.
    ///
    /// This should be called by a compliant ERC-1155 contract if the intended recipient is a smart
    /// contract.
    ///
    /// If the smart contract implementing this interface accepts token transfers then it must
    /// return `BATCH_ON_ERC_1155_RECEIVED_SELECTOR` from this function. To reject a transfer it must revert.
    ///
    /// Any callers must revert if they receive anything other than `BATCH_ON_ERC_1155_RECEIVED_SELECTOR` as a return
    /// value.
    #[ink(message, selector = 0xBC197C81)]
    fn on_batch_received(
        &mut self,
        operator: AccountId,
        from: AccountId,
        token_ids: Vec<TokenId>,
        values: Vec<Balance>,
        data: Vec<u8>,
    ) -> Vec<u8>;
}

// use erc1155::TokenId;
use ink_env::AccountId;
use ink_lang as ink;
#[ink::trait_definition]
pub trait IPayProxy {
    /// Query your Profile NFT's followers max supply
    /// newMax:  followers new max supply of Profile NFT
    /// theMax:  followers the max supply of Profile NFT
    #[ink(message)]
    fn query_pay(
        &self,
        account: AccountId,
        new_max: TokenId,
        _the_max: TokenId,
    ) -> (AccountId, AccountId, TokenId);
}

/// Hex space is a Web3 social network protocol . It aims to ena
/// and form a complete combinable, users-owned decentralized social network.
#[ink::contract]
mod hex_space {
    use crate::Erc1155;
    use crate::IPayProxy;
    use crate::Result;
    use crate::TokenId;
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
    #[derive(Default, SpreadAllocate)]
    pub struct HexSpace {
        /// Tracks the balances of accounts across the different tokens that they might be holding.
        balances: Mapping<(AccountId, TokenId), Balance>,
        /// Which accounts (called operators) have been approved to spend funds on behalf of an owner.
        approvals: Mapping<(Owner, Operator), ()>,
        /// A unique identifier for the tokens which have been minted (and are therefore supported)
        /// by this contract.
        token_id_nonce: TokenId,
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
        /// The  contract deployer address.
        owner: AccountId,
    }

    type Owner = AccountId;
    type Operator = AccountId;

    /// Indicate that a token transfer has occured.
    ///
    /// This must be emitted even if a zero value transfer occurs.
    /// While mint (the follow action), parameter from is None, to is follower address, id is serialization of the address being followed.
    /// While burn (the unfollow action), parameter from is follower's address, to is None, id is serialization of the address being followed.
    /// eg: value always 1
    #[ink(event)]
    pub struct TransferSingle {
        /// operator: operator of transaction
        #[ink(topic)]
        operator: Option<AccountId>,
        /// from: Profile NFT old owner
        #[ink(topic)]
        from: Option<AccountId>,
        /// to: Profile NFT new owner
        #[ink(topic)]
        to: Option<AccountId>,
        /// token_id: Profile NFT ID
        token_id: TokenId,
        /// value: Profile NFT value
        value: Balance,
    }

    /// Indicate that a token transfer has occured.
    ///
    /// This must be emitted even if a zero value transfer occurs.
    /// ids is a set of serializations of addresses being followed.
    #[ink(event)]
    pub struct TransferBatch {
        /// operator: operator of transaction
        #[ink(topic)]
        operator: Option<AccountId>,
        /// from: Profile NFT old owner
        #[ink(topic)]
        from: Option<AccountId>,
        /// to: Profile NFT new owner
        #[ink(topic)]
        to: Option<AccountId>,
        /// token_ids: Profile NFT ID's list
        token_ids: Vec<TokenId>,
        /// values: Profile NFT ID value's list
        values: Vec<Balance>,
    }

    /// Indicate that an approval event has happened.
    #[ink(event)]
    pub struct ApprovalForAll {
        #[ink(topic)]
        owner: AccountId,
        #[ink(topic)]
        operator: AccountId,
        approved: bool,
    }

    /// Indicate that a token's URI has been updated.
    #[ink(event)]
    pub struct Uri {
        pub value: ink_prelude::string::String,
        #[ink(topic)]
        pub token_id: TokenId,
    }
    /// Indicate that a mint event has happened.
    #[ink(event)]
    pub struct Mint {
        /// account: Profile NFT new owner
        #[ink(topic)]
        pub account: AccountId,
        /// owner: operator of transaction
        #[ink(topic)]
        pub owner: AccountId,
        /// token_id: Profile NFT ID
        #[ink(topic)]
        pub token_id: u128,
    }

    /// Indicate that a mintbatch event has happened.
    #[ink(event)]
    pub struct MintBatch {
        /// accounts: Profile NFT new owners
        #[ink(topic)]
        pub accounts: Vec<AccountId>,
        /// owner: operator of transaction
        #[ink(topic)]
        pub owner: AccountId,
        /// token_ids: Profile NFT ID's list
        #[ink(topic)]
        pub token_ids: Vec<u128>,
    }

    /// Indicate that a mintbatch event has happened.
    #[ink(event)]
    pub struct Burn {
        /// account: Profile NFT new owner
        #[ink(topic)]
        pub account: AccountId,
        /// owner: operator of transaction
        #[ink(topic)]
        pub owner: AccountId,
        /// token_id: Profile NFT ID
        #[ink(topic)]
        pub token_id: TokenId,
    }

    /// Indicate that a mintbatch event has happened.
    #[ink(event)]
    pub struct BurnBatch {
        /// accounts: Profile NFT owners
        #[ink(topic)]
        pub accounts: Vec<AccountId>,
        /// owner: operator of transaction
        #[ink(topic)]
        pub owner: AccountId,
        /// token_ids: Profile NFT ID's list
        #[ink(topic)]
        pub token_ids: Vec<TokenId>,
    }

    //Web3 Ascii code 87+101+98+51 = 8195
    const _MAX_SUPPLY: u128 = 8195;

    /// Errors that can occur upon calling this contract.
    #[derive(Copy, Clone, Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(::scale_info::TypeInfo))]
    pub enum Error {
        /// This token ID has not yet been created by the contract.
        UnexistentToken,
        /// The caller tried to sending tokens to the zero-address (`0x00`).
        ZeroAddressTransfer,
        /// The caller is not approved to transfer tokens on behalf of the account.
        NotApproved,
        /// The account does not have enough funds to complete the transfer.
        InsufficientBalance,
        /// An account does not need to approve themselves to transfer tokens.
        SelfApproval,
        /// The number of tokens being transferred does not match the specified number of transfers.
        BatchTransferMismatch,
        /// Returned if the call failed.
        TransactionFailed,
    }

    impl HexSpace {
        /// Constructor that initializes the `u32` value to the given `version`.
        /// the `Hash` value to the given `code_hash`.
        #[ink(constructor)]
        #[cfg_attr(test, allow(unused_variables))]
        pub fn new() -> Self {
            ink_lang::utils::initialize_contract(|contract: &mut Self| {
                contract.owner = Self::env().caller();
                contract._uri.insert(
                    Self::env().account_id(),
                    &TokenURIInfo {
                        name: String::new(),
                        image: String::new(),
                        max_supply: 2022,
                        properties: String::new(),
                    },
                );
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

            let json= format!("'name':{},'image':{},'maxSupply':{},'tokenSupply':{},'totalBalance':{} ,'properties':{}",
                      info.name,info.image,info.max_supply,followers,followings,info.properties) ;
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
            assert!(self.owner == self.env().caller(), "HexSpace: only Owner");
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
                    if self.env().transfer(receiver, value).is_err() {
                        panic!(
                    "requested transfer failed. this can be the case if the contract does not\
                     have sufficient free funds or if the transfer would have brought the\
                     contract's balance below minimum balance.")
                    }
                } else {
                    self.token_call(
                        token,
                        [0x0b, 0x39, 0x6f, 0x18].to_vec(), //transfer_from
                        account,
                        receiver,
                        amount,
                    );
                }
            }
        }

        /// Call selector of the 'token' ERC20 address
        /// # Fields
        /// token: the address of the ERC20 token contract
        /// selector:the interface method of the ERC20 token contract
        /// account: the 'account' parameter of the  method of the ERC20 token contract
        /// receiver: the 'receiver' parameter of the  method of the ERC20 token contract
        /// amount: the 'amount' parameter of the  method of the ERC20 token contract
        #[cfg_attr(test, allow(unused_variables))]
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
                let selector = [selector[0], selector[1], selector[2], selector[3]]; // [0x0b, 0x39, 0x6f, 0x18];//transfer_from
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
        ///
        /// # Panics
        ///
        /// If `new_max` is less than or equal to   `the_max` .
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
        ///
        /// # Panics
        ///
        /// If `new_max` is greater than or equal to   `the_max` .
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
        pub fn mint_hex(&mut self, account: AccountId) {
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
        ///
        /// # Panics
        ///
        /// If `operator` is  equal to `account` .
        /// If `operator` aleady  followed `account` .
        /// If  the token_supply of `account` is greater than or equal to  the max_supply of `account` .
        fn _internal_mint(&mut self, operator: AccountId, account: AccountId) {
            let token_id = self.account_id_to_token_id(account);
            assert!(operator != account, "HexSpace: cannot mint your own NFT");
            assert!(
                self.balance_of_hex(operator, account) == 0,
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
            assert!(
                self.mint_to(operator, token_id, 1).is_ok(),
                "HexSpace: call erc1155 mint_to failed"
            );
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
                if self.balance_of_hex(operator, account) > 0 {
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
            assert!(
                self.mint_to_batch(operator, ids.clone(), amounts).is_ok(),
                "HexSpace: call erc1155 mint_to_batch failed"
            );
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
        pub fn burn_hex(&mut self, account: AccountId) {
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
        ///
        /// # Panics
        ///
        /// If `operator` does not  follow    `account` .
        /// If  the token_supply of    `account` is  equal to  zero .
        /// If  the total_balance of    `operator` is  equal to  zero .
        fn _internal_burn(&mut self, operator: AccountId, account: AccountId) {
            let token_id = self.account_id_to_token_id(account);
            assert!(
                self.balance_of(operator, token_id) > 0,
                "HexSpace:  token not existed"
            );
            assert!(
                self.burn(operator, token_id, 1).is_ok(),
                "HexSpace: call erc1155 burn failed"
            );
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
        pub fn burn_batch_hex(&mut self, account: Vec<AccountId>) {
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
        ///
        /// # Panics
        ///
        /// If  the token_supply of    `account` is  equal to  zero .
        /// If  the total_balance of    `operator` is  equal to  zero .
        fn _internal_burn_batch(&mut self, operator: AccountId, accounts: Vec<AccountId>) {
            let mut ids = Vec::new();
            let mut amounts = Vec::new();
            for &account in &accounts {
                let token_id = self.account_id_to_token_id(account);
                if self.balance_of_hex(operator, account) == 0 {
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

            assert!(
                self.burn_batch(operator, ids.clone(), amounts).is_ok(),
                "HexSpace: call erc1155 burn_batch failed"
            );
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
        /// # Panics
        ///
        /// If  the token_id is the follower of `to`.
        /// If  `from' is not the follower of `to`.
        /// If  the total_balance of  `from' is less than `value` .
        #[ink(message)]
        #[cfg_attr(test, allow(unused_variables))]
        pub fn safe_transfer_from_hex(
            &mut self,
            from: AccountId,
            to: AccountId,
            token_id: AccountId,
            value: Balance,
            data: Vec<u8>,
        ) {
            let caller = self.env().caller();
            let caller_id = self.account_id_to_token_id(caller);
            let token_id = self.account_id_to_token_id(token_id);
            assert!(
                self.balance_of(to, token_id) == 0,
                "HexSpace: already minted"
            );
            assert!(
                self.balance_of(to, caller_id) > 0,
                "HexSpace: receiver hasn't minted sender's NFT"
            );

            assert!(
                self.safe_transfer_from(from, to, token_id, value, data)
                    .is_ok(),
                "HexSpace: call erc1155 safe_transfer_from failed"
            );
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
        /// # Panics
        ///
        /// If  the length of `token_ids`  is not equal to  the length of `values`.
        /// If  the token_id is the follower of `to`.
        /// If  `from' is not the follower of `to`.
        /// If  the total_balance of  `from' is less than `value` .
        #[ink(message)]
        #[cfg_attr(test, allow(unused_variables))]
        pub fn safe_batch_transfer_from_hex(
            &mut self,
            from: AccountId,
            to: AccountId,
            token_ids: Vec<AccountId>,
            values: Vec<Balance>,
            data: Vec<u8>,
        ) {
            assert!(
                token_ids.len() > 0 && token_ids.len() == values.len(),
                "HexSpace: length of ids and amounts mismatch",
            );
            let mut amount = 0;
            let transfers = token_ids.iter().zip(values.iter());
            for (&id, &v) in transfers.clone() {
                let id = self.account_id_to_token_id(id);
                assert!(self.balance_of(to, id) == 0, "HexSpace: already minted");
                amount += v;
            }

            let caller = self.env().caller();
            let caller_id = self.account_id_to_token_id(caller);
            assert!(
                self.balance_of(to, caller_id) > 0,
                "HexSpace: receiver hasn't minted sender's NFT"
            );
            let token_ids: Vec<TokenId> = token_ids
                .into_iter()
                .map(|id| self.account_id_to_token_id(id))
                .collect();

            assert!(
                self.safe_batch_transfer_from(from, to, token_ids, values, data)
                    .is_ok(),
                "HexSpace: call erc1155 safe_batch_transfer_from failed"
            );
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
        #[cfg_attr(test, allow(unused_variables))]
        pub fn balance_of_hex(&self, owner: AccountId, token_id: AccountId) -> Balance {
            let token_id = self.account_id_to_token_id(token_id);

            self.balance_of(owner, token_id)
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
        #[cfg_attr(test, allow(unused_variables))]
        pub fn balance_of_batch_hex(
            &self,
            owners: Vec<AccountId>,
            token_ids: Vec<AccountId>,
        ) -> Vec<Balance> {
            let mut output = Vec::new();
            for &t in &token_ids {
                let token_id = self.account_id_to_token_id(t);
                output.push(token_id);
            }

            self.balance_of_batch(owners, output)
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
            ans
        }
        // =======================ERC-1155=========================
        /// Create the initial supply for a token.
        ///
        /// The initial supply will be provided to the caller (a.k.a the minter), and the
        /// `token_id` will be assigned by the smart contract.
        ///
        /// Note that as implemented anyone can create tokens. If you were to instantiate
        /// this contract in a production environment you'd probably want to lock down
        /// the addresses that are allowed to create tokens.
        #[ink(message)]
        pub fn create(&mut self, value: Balance) -> TokenId {
            let caller = self.env().caller();

            // Given that TokenId is a `u128` the likelihood of this overflowing is pretty slim.
            self.token_id_nonce += 1;
            self.balances.insert(&(caller, self.token_id_nonce), &value);

            // Emit transfer event but with mint semantics
            self.env().emit_event(TransferSingle {
                operator: Some(caller),
                from: None,
                to: if value == 0 { None } else { Some(caller) },
                token_id: self.token_id_nonce,
                value,
            });

            self.token_id_nonce
        }

        /// Mint a `value` amount of `token_id` tokens.
        ///
        /// It is assumed that the token has already been `create`-ed. The newly minted supply will
        /// be assigned to the caller (a.k.a the minter).
        ///
        /// Note that as implemented anyone can mint tokens. If you were to instantiate
        /// this contract in a production environment you'd probably want to lock down
        /// the addresses that are allowed to mint tokens.
        #[ink(message)]
        pub fn mint(&mut self, token_id: TokenId, value: Balance) -> Result<()> {
            ensure!(token_id <= self.token_id_nonce, Error::UnexistentToken);

            let caller = self.env().caller();
            self.balances.insert(&(caller, token_id), &value);

            // Emit transfer event but with mint semantics
            self.env().emit_event(TransferSingle {
                operator: Some(caller),
                from: None,
                to: Some(caller),
                token_id,
                value,
            });

            Ok(())
        }

        /// Mint a `value` amount of `token_id` tokens to the given account.
        ///
        /// The newly minted supply will
        /// be assigned to the given account.
        ///
        /// Note that as implemented anyone can mint tokens. If you were to instantiate
        /// this contract in a production environment you'd probably want to lock down
        /// the addresses that are allowed to mint tokens.
        #[ink(message)]
        pub fn mint_to(&mut self, to: AccountId, token_id: TokenId, value: Balance) -> Result<()> {
            let caller = self.env().caller();
            ensure!(to != AccountId::default(), Error::ZeroAddressTransfer);
            self.balances.insert(&(to, token_id), &value);

            // Emit transfer event but with mint semantics
            self.env().emit_event(TransferSingle {
                operator: Some(caller),
                from: None,
                to: Some(to),
                token_id,
                value,
            });

            Ok(())
        }

        /// Batch mint these `values` amount of `token_ids` tokens to the given account.
        ///
        /// The newly minted supply will
        /// be assigned to the given account.
        ///
        /// Note that as implemented anyone can mint tokens. If you were to instantiate
        /// this contract in a production environment you'd probably want to lock down
        /// the addresses that are allowed to mint tokens.
        #[ink(message)]
        pub fn mint_to_batch(
            &mut self,
            to: AccountId,
            token_ids: Vec<TokenId>,
            values: Vec<Balance>,
        ) -> Result<()> {
            let caller = self.env().caller();
            ensure!(to != AccountId::default(), Error::ZeroAddressTransfer);

            let transfers = token_ids.iter().zip(values.iter());
            for (&token_id, &value) in transfers {
                self.balances.insert(&(to, token_id), &value);
            }
            // Emit transfer event but with mint semantics
            self.env().emit_event(TransferBatch {
                operator: Some(caller),
                from: None,
                to: Some(to),
                token_ids,
                values,
            });

            Ok(())
        }
        /// Deletes an existing token.
        /// Deletes `value` tokens on the behalf of `from`.
        ///
        /// This can be used to allow a contract to delete tokens on ones behalf and/or
        /// to charge fees in sub-currencies.
        #[ink(message)]
        pub fn burn(&mut self, from: AccountId, token_id: TokenId, value: Balance) -> Result<()> {
            ensure!(from != AccountId::default(), Error::ZeroAddressTransfer);

            let caller = self.env().caller();
            if caller != from {
                ensure!(self.is_approved_for_all(from, caller), Error::NotApproved);
            }
            let mut sender_balance = self
                .balances
                .get(&(from, token_id))
                .expect("Caller should have ensured that `from` holds `token_id`.");
            sender_balance -= value;
            self.balances.insert(&(from, token_id), &sender_balance);

            let caller = self.env().caller();
            self.env().emit_event(TransferSingle {
                operator: Some(caller),
                from: Some(from),
                to: None,
                token_id,
                value,
            });
            Ok(())
        }

        /// Deletes the existing tokens.
        /// Deletes `values` tokens on the behalf of `from`.
        ///
        /// This can be used to allow a contract to delete tokens on ones behalf and/or
        /// to charge fees in sub-currencies.
        #[ink(message)]
        pub fn burn_batch(
            &mut self,
            from: AccountId,
            token_ids: Vec<TokenId>,
            values: Vec<Balance>,
        ) -> Result<()> {
            ensure!(from != AccountId::default(), Error::ZeroAddressTransfer);

            let caller = self.env().caller();
            if caller != from {
                ensure!(self.is_approved_for_all(from, caller), Error::NotApproved);
            }

            let transfers = token_ids.iter().zip(values.iter());
            for (&token_id, &value) in transfers {
                let mut sender_balance = self
                    .balances
                    .get(&(from, token_id))
                    .expect("Caller should have ensured that `from` holds `token_id`.");
                sender_balance -= value;
                self.balances.insert(&(from, token_id), &sender_balance);
            }

            let caller = self.env().caller();
            self.env().emit_event(TransferBatch {
                operator: Some(caller),
                from: Some(from),
                to: None,
                token_ids,
                values,
            });
            Ok(())
        }

        // Helper function for performing single token transfers.
        //
        // Should not be used directly since it's missing certain checks which are important to the
        // ERC-1155 standard (it is expected that the caller has already performed these).
        //
        // # Panics
        //
        // If `from` does not hold any `token_id` tokens.
        fn perform_transfer(
            &mut self,
            from: AccountId,
            to: AccountId,
            token_id: TokenId,
            value: Balance,
        ) {
            let mut sender_balance = self
                .balances
                .get(&(from, token_id))
                .expect("Caller should have ensured that `from` holds `token_id`.");
            sender_balance -= value;
            self.balances.insert(&(from, token_id), &sender_balance);

            let mut recipient_balance = self.balances.get(&(to, token_id)).unwrap_or(0);
            recipient_balance += value;
            self.balances.insert(&(to, token_id), &recipient_balance);

            let caller = self.env().caller();
            self.env().emit_event(TransferSingle {
                operator: Some(caller),
                from: Some(from),
                to: Some(from),
                token_id,
                value,
            });
        }

        // Check if the address at `to` is a smart contract which accepts ERC-1155 token transfers.
        //
        // If they're a smart contract which **doesn't** accept tokens transfers this call will
        // revert. Otherwise we risk locking user funds at in that contract with no chance of
        // recovery.
        #[cfg_attr(test, allow(unused_variables))]
        fn transfer_acceptance_check(
            &mut self,
            caller: AccountId,
            from: AccountId,
            to: AccountId,
            token_id: TokenId,
            value: Balance,
            data: Vec<u8>,
        ) {
            // This is disabled during tests due to the use of `invoke_contract()` not being
            // supported (tests end up panicking).
            #[cfg(not(test))]
            {
                use ink_env::call::{build_call, Call, ExecutionInput, Selector};
                use crate::ON_ERC_1155_RECEIVED_SELECTOR;

                // If our recipient is a smart contract we need to see if they accept or
                // reject this transfer. If they reject it we need to revert the call.
                let params = build_call::<Environment>()
                    .call_type(Call::new().callee(to).gas_limit(5000))
                    .exec_input(
                        ExecutionInput::new(Selector::new(ON_ERC_1155_RECEIVED_SELECTOR))
                            .push_arg(caller)
                            .push_arg(from)
                            .push_arg(token_id)
                            .push_arg(value)
                            .push_arg(data),
                    )
                    .returns::<Vec<u8>>()
                    .params();

                match ink_env::invoke_contract(&params) {
                    Ok(v) => {
                        ink_env::debug_println!(
                            "Received return value \"{:?}\" from contract {:?}",
                            v,
                            from
                        );
                        assert_eq!(
                            v,
                            &ON_ERC_1155_RECEIVED_SELECTOR[..],
                            "The recipient contract at {:?} does not accept token transfers.\n
                            Expected: {:?}, Got {:?}",
                            to,
                            ON_ERC_1155_RECEIVED_SELECTOR,
                            v
                        )
                    }
                    Err(e) => {
                        match e {
                            ink_env::Error::CodeNotFound | ink_env::Error::NotCallable => {
                                // Our recipient wasn't a smart contract, so there's nothing more for
                                // us to do
                                ink_env::debug_println!(
                                    "Recipient at {:?} from is not a smart contract ({:?})",
                                    from,
                                    e
                                );
                            }
                            _ => {
                                // We got some sort of error from the call to our recipient smart
                                // contract, and as such we must revert this call
                                panic!("Got error \"{:?}\" while trying to call {:?}", e, from)
                            }
                        }
                    }
                }
            }
        }
    }
    impl super::Erc1155 for HexSpace {
        #[ink(message)]
        fn safe_transfer_from(
            &mut self,
            from: AccountId,
            to: AccountId,
            token_id: TokenId,
            value: Balance,
            data: Vec<u8>,
        ) -> Result<()> {
            let caller = self.env().caller();
            if caller != from {
                ensure!(self.is_approved_for_all(from, caller), Error::NotApproved);
            }

            ensure!(to != AccountId::default(), Error::ZeroAddressTransfer);

            let balance = self.balance_of(from, token_id);
            ensure!(balance >= value, Error::InsufficientBalance);

            self.perform_transfer(from, to, token_id, value);
            self.transfer_acceptance_check(caller, from, to, token_id, value, data);

            Ok(())
        }

        #[ink(message)]
        fn safe_batch_transfer_from(
            &mut self,
            from: AccountId,
            to: AccountId,
            token_ids: Vec<TokenId>,
            values: Vec<Balance>,
            data: Vec<u8>,
        ) -> Result<()> {
            let caller = self.env().caller();
            if caller != from {
                ensure!(self.is_approved_for_all(from, caller), Error::NotApproved);
            }

            ensure!(to != AccountId::default(), Error::ZeroAddressTransfer);
            ensure!(!token_ids.is_empty(), Error::BatchTransferMismatch);
            ensure!(
                token_ids.len() == values.len(),
                Error::BatchTransferMismatch,
            );

            let transfers = token_ids.iter().zip(values.iter());
            for (&id, &v) in transfers.clone() {
                let balance = self.balance_of(from, id);
                ensure!(balance >= v, Error::InsufficientBalance);
            }

            for (&id, &v) in transfers {
                self.perform_transfer(from, to, id, v);
            }

            // Can use the any token ID/value here, we really just care about knowing if `to` is a
            // smart contract which accepts transfers
            self.transfer_acceptance_check(caller, from, to, token_ids[0], values[0], data);

            Ok(())
        }

        #[ink(message)]
        fn balance_of(&self, owner: AccountId, token_id: TokenId) -> Balance {
            self.balances.get(&(owner, token_id)).unwrap_or(0)
        }

        #[ink(message)]
        fn balance_of_batch(
            &self,
            owners: Vec<AccountId>,
            token_ids: Vec<TokenId>,
        ) -> Vec<Balance> {
            let mut output = Vec::new();
            for o in &owners {
                for t in &token_ids {
                    let amount = self.balance_of(*o, *t);
                    output.push(amount);
                }
            }
            output
        }

        #[ink(message)]
        fn set_approval_for_all(&mut self, operator: AccountId, approved: bool) -> Result<()> {
            let caller = self.env().caller();
            ensure!(operator != caller, Error::SelfApproval);

            if approved {
                self.approvals.insert((&caller, &operator), &());
            } else {
                self.approvals.remove((&caller, &operator));
            }

            self.env().emit_event(ApprovalForAll {
                owner: caller,
                operator,
                approved,
            });

            Ok(())
        }

        #[ink(message)]
        fn is_approved_for_all(&self, owner: AccountId, operator: AccountId) -> bool {
            self.approvals.get((&owner, &operator)).is_some()
        }
    }

    impl super::Erc1155TokenReceiver for HexSpace {
        #[ink(message, selector = 0xF23A6E61)]
        fn on_received(
            &mut self,
            _operator: AccountId,
            _from: AccountId,
            _token_id: TokenId,
            _value: Balance,
            _data: Vec<u8>,
        ) -> Vec<u8> {
            // The ERC-1155 standard dictates that if a contract does not accept token transfers
            // directly to the contract, then the contract must revert.
            //
            // This prevents a user from unintentionally transferring tokens to a smart contract
            // and getting their funds stuck without any sort of recovery mechanism.
            //
            // Note that the choice of whether or not to accept tokens is implementation specific,
            // and we've decided to not accept them in this implementation.
            unimplemented!("This smart contract does not accept token transfer.")
        }

        #[ink(message, selector = 0xBC197C81)]
        fn on_batch_received(
            &mut self,
            _operator: AccountId,
            _from: AccountId,
            _token_ids: Vec<TokenId>,
            _values: Vec<Balance>,
            _data: Vec<u8>,
        ) -> Vec<u8> {
            // The ERC-1155 standard dictates that if a contract does not accept token transfers
            // directly to the contract, then the contract must revert.
            //
            // This prevents a user from unintentionally transferring tokens to a smart contract
            // and getting their funds stuck without any sort of recovery mechanism.
            //
            // Note that the choice of whether or not to accept tokens is implementation specific,
            // and we've decided to not accept them in this implementation.
            unimplemented!("This smart contract does not accept batch token transfers.")
        }
    }

    impl super::IPayProxy for HexSpace {
        /// Query your Profile NFT's followers max supply
        /// newMax:  followers new max supply of Profile NFT
        /// theMax:  followers the max supply of Profile NFT
        #[ink(message)]
        fn query_pay(
            &self,
            account: AccountId,
            new_max: TokenId,
            _the_max: TokenId,
        ) -> (AccountId, AccountId, TokenId) {
            let (token, receiver, amount) = (account, account, new_max);
            (token, receiver, amount)
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

        type Event = <HexSpace as ::ink_lang::reflect::ContractEventBase>::Type;

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
                    value: b"HexSpace::Uri",
                    prefix: b"",
                }),
                encoded_into_hash(&PrefixedValue {
                    prefix: b"HexSpace::Uri::token_id",
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
                    value: b"HexSpace::Mint",
                    prefix: b"",
                }),
                encoded_into_hash(&PrefixedValue {
                    prefix: b"HexSpace::Mint::account",
                    value: &expected_account,
                }),
                encoded_into_hash(&PrefixedValue {
                    prefix: b"HexSpace::Mint::owner",
                    value: &expected_owner,
                }),
                encoded_into_hash(&PrefixedValue {
                    prefix: b"HexSpace::Mint::token_id",
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
                    value: b"HexSpace::MintBatch",
                    prefix: b"",
                }),
                encoded_into_hash(&PrefixedValue {
                    prefix: b"HexSpace::MintBatch::accounts",
                    value: &expected_accounts,
                }),
                encoded_into_hash(&PrefixedValue {
                    prefix: b"HexSpace::MintBatch::owner",
                    value: &expected_owner,
                }),
                encoded_into_hash(&PrefixedValue {
                    prefix: b"HexSpace::MintBatch::token_ids",
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
                    value: b"HexSpace::Burn",
                    prefix: b"",
                }),
                encoded_into_hash(&PrefixedValue {
                    prefix: b"HexSpace::Burn::account",
                    value: &expected_account,
                }),
                encoded_into_hash(&PrefixedValue {
                    prefix: b"HexSpace::Burn::owner",
                    value: &expected_owner,
                }),
                encoded_into_hash(&PrefixedValue {
                    prefix: b"HexSpace::Burn::token_id",
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
                    value: b"HexSpace::BurnBatch",
                    prefix: b"",
                }),
                encoded_into_hash(&PrefixedValue {
                    prefix: b"HexSpace::BurnBatch::accounts",
                    value: &expected_accounts,
                }),
                encoded_into_hash(&PrefixedValue {
                    prefix: b"HexSpace::BurnBatch::owner",
                    value: &expected_owner,
                }),
                encoded_into_hash(&PrefixedValue {
                    prefix: b"HexSpace::BurnBatch::token_ids",
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
            let contract = ink_env::account_id::<ink_env::DefaultEnvironment>();
            ink_env::test::set_callee::<ink_env::DefaultEnvironment>(contract);
            set_sender(alice());
            let mut hex_space = HexSpace::new();
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

            hex_space.balances.insert((alice(), 1), &10);
            hex_space.balances.insert((alice(), 2), &20);
            hex_space.balances.insert((bob(), 1), &10);

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
        #[should_panic]
        fn set_pay_proxy_fail_if_not_owner() {
            let mut hex_space = init_contract();
            set_sender(bob());
            hex_space.set_pay_proxy(charlie());
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
        #[should_panic]
        fn increase_max_supply_fail() {
            let mut hex_space = init_contract();
            let operator = alice();
            set_sender(operator);

            hex_space.increase_max_supply(2021);
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
        #[should_panic]
        fn decrease_max_supply_fail() {
            let mut hex_space = init_contract();
            let operator = alice();
            set_sender(operator);

            hex_space.decrease_max_supply(2023);
        }
        #[ink::test]
        fn minting_tokens_hex_works() {
            let mut hex_space = init_contract();
            let operator = alice();
            set_sender(operator);
            hex_space.mint_hex(bob());
            let emitted_events = ink_env::test::recorded_events().collect::<Vec<_>>();
            assert_eq!(2, emitted_events.len());
            let toke_id = hex_space.account_id_to_token_id(bob());

            assert_mint_event(&emitted_events[1], bob(), operator, toke_id);
        }

        #[ink::test]
        #[should_panic]
        fn minting_tokens_fails_if_operator_equal_to_account() {
            let mut hex_space = init_contract();
            let operator = alice();
            set_sender(operator);
            hex_space.mint_hex(operator);
        }
        #[ink::test]
        #[should_panic]
        fn minting_tokens_fails() {
            let mut hex_space = init_contract();
            let operator = alice();
            set_sender(operator);
            let token_id = hex_space.account_id_to_token_id(bob());
            hex_space.balances.insert((alice(), token_id), &1);
            hex_space.mint_hex(bob());
        }
        #[ink::test]
        #[should_panic]
        fn minting_tokens_fails_if_total_supply_equal_max_supply() {
            let mut hex_space = init_contract();
            let operator = alice();
            set_sender(operator);
            hex_space._uri.insert(
                bob(),
                &TokenURIInfo {
                    name: String::new(),
                    image: String::new(),
                    max_supply: 2022,
                    properties: String::new(),
                },
            );
            hex_space._token_supply.insert(bob(), &2022);
            hex_space.mint_hex(bob());
        }
        #[ink::test]
        fn mint_by_origin_tokens_works() {
            let mut hex_space = init_contract();
            let operator = alice();
            set_sender(operator);
            hex_space.mint_by_origin(bob());
            let emitted_events = ink_env::test::recorded_events().collect::<Vec<_>>();
            assert_eq!(2, emitted_events.len());
            let toke_id = hex_space.account_id_to_token_id(bob());

            assert_mint_event(&emitted_events[1], bob(), operator, toke_id);
        }

        #[ink::test]
        fn mint_batch() {
            let mut hex_space = init_contract();
            let operator = alice();
            set_sender(operator);
            let accounts_token_ids = vec![bob(), charlie()];
            hex_space.mint_batch(accounts_token_ids.clone());
            let emitted_events = ink_env::test::recorded_events().collect::<Vec<_>>();
            assert_eq!(2, emitted_events.len());
            let token_ids: Vec<TokenId> = accounts_token_ids
                .iter()
                .map(|&id| hex_space.account_id_to_token_id(id))
                .collect();
            assert_mint_batch_event(&emitted_events[1], accounts_token_ids, operator, token_ids);
        }
        #[ink::test]
        fn mint_batch_by_origin() {
            let mut hex_space = init_contract();
            let operator = alice();
            set_sender(operator);
            let accounts_token_ids = vec![bob(), charlie()];
            hex_space.mint_batch_by_origin(accounts_token_ids.clone());
            let emitted_events = ink_env::test::recorded_events().collect::<Vec<_>>();
            assert_eq!(2, emitted_events.len());
            let token_ids: Vec<TokenId> = accounts_token_ids
                .iter()
                .map(|&id| hex_space.account_id_to_token_id(id))
                .collect();
            assert_mint_batch_event(&emitted_events[1], accounts_token_ids, operator, token_ids);
        }

        #[ink::test]
        fn burning_tokens_works() {
            let mut hex_space = init_contract();
            let operator = alice();
            set_sender(operator);
            let toke_id = hex_space.account_id_to_token_id(bob());
            hex_space.balances.insert(&(operator, toke_id), &1);
            hex_space.burn_hex(bob());
            let emitted_events = ink_env::test::recorded_events().collect::<Vec<_>>();
            assert_eq!(2, emitted_events.len());

            assert_burn_event(&emitted_events[1], bob(), operator, toke_id);
        }

        #[ink::test]
        #[should_panic]
        fn burning_tokens_fails_if_token_supply_is_zero() {
            let mut hex_space = init_contract();
            let operator = django();
            set_sender(operator);
            let account = eve();
            hex_space.burn_hex(account);
        }
        #[ink::test]
        #[should_panic]
        fn burning_tokens_fails_if_total_balance_is_zero() {
            let mut hex_space = init_contract();
            let operator = django();
            set_sender(operator);
            let account = eve();
            hex_space._token_supply.insert(&account, &15);
            hex_space.burn_hex(account);
        }
        #[ink::test]
        fn burn_by_origin_tokens_works() {
            let mut hex_space = init_contract();
            let operator = alice();
            set_sender(operator);
            let toke_id = hex_space.account_id_to_token_id(bob());
            hex_space.balances.insert(&(operator, toke_id), &1);
            hex_space.burn_by_origin(bob());
            let emitted_events = ink_env::test::recorded_events().collect::<Vec<_>>();
            assert_eq!(2, emitted_events.len());

            assert_burn_event(&emitted_events[1], bob(), operator, toke_id);
        }

        #[ink::test]
        fn burn_batch_works() {
            let mut hex_space = init_contract();
            let operator = alice();
            set_sender(operator);
            let accounts_token_ids = vec![bob(), charlie()];
            let token_ids: Vec<TokenId> = accounts_token_ids
                .iter()
                .map(|&id| hex_space.account_id_to_token_id(id))
                .collect();
            hex_space.balances.insert((alice(), token_ids[0]), &1);
            hex_space.balances.insert((alice(), token_ids[1]), &1);
            hex_space.burn_batch_hex(accounts_token_ids.clone());
            let emitted_events = ink_env::test::recorded_events().collect::<Vec<_>>();
            assert_eq!(2, emitted_events.len());
            assert_burn_batch_event(&emitted_events[1], accounts_token_ids, operator, token_ids);
        }
        #[ink::test]
        #[should_panic]
        fn burning_batch_tokens_fails_if_token_supply_is_zero() {
            let mut hex_space = init_contract();
            let operator = django();
            set_sender(operator);
            let account = eve();
            let accounts_token_ids = vec![account];
            let token_ids: Vec<TokenId> = accounts_token_ids
                .iter()
                .map(|&id| hex_space.account_id_to_token_id(id))
                .collect();
            hex_space.balances.insert((operator, token_ids[0]), &1);
            hex_space.burn_batch_hex(accounts_token_ids.clone());
        }
        #[ink::test]
        #[should_panic]
        fn burning_batch_tokens_fails_if_total_balance_is_zero() {
            let mut hex_space = init_contract();
            let operator = django();
            set_sender(operator);
            let account = eve();
            hex_space._token_supply.insert(&account, &15);
            let account = eve();
            let accounts_token_ids = vec![account];
            let token_ids: Vec<TokenId> = accounts_token_ids
                .iter()
                .map(|&id| hex_space.account_id_to_token_id(id))
                .collect();
            hex_space.balances.insert((operator, token_ids[0]), &1);
            hex_space.burn_batch_hex(accounts_token_ids.clone());
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
            hex_space.balances.insert((alice(), token_ids[0]), &1);
            hex_space.balances.insert((alice(), token_ids[1]), &1);
            hex_space.burn_batch_by_origin(accounts_token_ids.clone());
            let emitted_events = ink_env::test::recorded_events().collect::<Vec<_>>();
            assert_eq!(2, emitted_events.len());

            assert_burn_batch_event(&emitted_events[1], accounts_token_ids, operator, token_ids);
        }

        #[ink::test]
        #[should_panic]
        fn sending_too_many_tokens_hex_fails() {
            let mut hex_space = init_contract();
            hex_space.safe_transfer_from_hex(bob(), charlie(), frank(), 99, vec![]);
        }

        #[ink::test]
        #[should_panic]
        fn sending_tokens_fails_if_insufficient_balance() {
            let burn: AccountId = [0; 32].into();

            let mut hex_space = init_contract();
            hex_space.safe_transfer_from_hex(bob(), burn, frank(), 100, vec![]);
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
        fn can_send_batch_tokens_hex() {
            let mut hex_space = init_contract();
            let operator = bob();
            set_sender(operator);
            hex_space
                .balances
                .insert(&(charlie(), hex_space.account_id_to_token_id(operator)), &1);
            hex_space
                .balances
                .insert(&(operator, hex_space.account_id_to_token_id(frank())), &5);
            hex_space
                .balances
                .insert(&(operator, hex_space.account_id_to_token_id(django())), &10);
            hex_space.safe_batch_transfer_from_hex(
                bob(),
                charlie(),
                vec![frank(), django()],
                vec![5, 10],
                vec![],
            );
        }

        #[ink::test]
        #[should_panic]
        fn rejects_batch_hex_if_lengths_dont_match() {
            let mut hex_space = init_contract();
            hex_space.safe_batch_transfer_from_hex(
                bob(),
                charlie(),
                vec![frank(), eve(), django()],
                vec![5],
                vec![],
            );
        }

        #[ink::test]
        #[should_panic]
        fn batch_transfers_hex_fail_if_len_is_zero() {
            let mut hex_space = init_contract();
            hex_space.safe_batch_transfer_from_hex(bob(), charlie(), vec![], vec![], vec![]);
        }
        #[ink::test]
        #[should_panic]
        fn batch_transfers_fail_if_balance_insufficient() {
            let mut hex_space = init_contract();
            hex_space.safe_batch_transfer_from_hex(
                bob(),
                charlie(),
                vec![frank(), eve(), django()],
                vec![50, 50, 50],
                vec![],
            );
        }
        #[ink::test]
        fn test_single_char() {
            let input_str = "a";
            let expected = "YQ==".to_string();

            let input_data = input_str.to_string();
            let hex_space = init_contract();
            let operator = alice();
            set_sender(operator);
            assert_eq!(hex_space.base64_encode(&input_data), expected);
        }

        #[ink::test]
        fn test_two_chars() {
            let input_str = "ab";
            let expected = "YWI=".to_string();

            let input_data = input_str.to_string();
            let hex_space = init_contract();
            let operator = alice();
            set_sender(operator);
            assert_eq!(hex_space.base64_encode(&input_data), expected);
        }

        #[ink::test]
        fn test_three_chars() {
            let input_str = "abc";
            let expected = "YWJj".to_string();

            let input_data = input_str.to_string();
            let hex_space = init_contract();
            let operator = alice();
            set_sender(operator);
            assert_eq!(hex_space.base64_encode(&input_data), expected);
        }

        #[ink::test]
        fn tests_short_string() {
            let input_str = "Hello, world!";
            let expected = "SGVsbG8sIHdvcmxkIQ==".to_string();

            let input_data = input_str.to_string();
            let hex_space = init_contract();
            let operator = alice();
            set_sender(operator);
            assert_eq!(hex_space.base64_encode(&input_data), expected);
        }

        #[ink::test]
        fn test_longer_string() {
            let input_str = "And here be a bit longer text. Let's see how it goes!";
            let expected =
                "QW5kIGhlcmUgYmUgYSBiaXQgbG9uZ2VyIHRleHQuIExldCdzIHNlZSBob3cgaXQgZ29lcyE="
                    .to_string();

            let input_data = input_str.to_string();
            let hex_space = init_contract();
            let operator = alice();
            set_sender(operator);
            assert_eq!(hex_space.base64_encode(&input_data), expected);
        }
        //============================ERC-1155=======================
        #[ink::test]
        fn can_get_correct_balance_of() {
            let erc = init_contract();

            assert_eq!(erc.balance_of(alice(), 1), 10);
            assert_eq!(erc.balance_of(alice(), 2), 20);
            assert_eq!(erc.balance_of(alice(), 3), 0);
            assert_eq!(erc.balance_of(bob(), 2), 0);
        }

        #[ink::test]
        fn can_get_correct_batch_balance_of() {
            let erc = init_contract();

            assert_eq!(
                erc.balance_of_batch(vec![alice()], vec![1, 2, 3]),
                vec![10, 20, 0]
            );
            assert_eq!(
                erc.balance_of_batch(vec![alice(), bob()], vec![1]),
                vec![10, 10]
            );

            assert_eq!(
                erc.balance_of_batch(vec![alice(), bob(), charlie()], vec![1, 2]),
                vec![10, 20, 10, 0, 0, 0]
            );
        }

        #[ink::test]
        fn can_send_tokens_between_accounts() {
            let mut erc = init_contract();

            assert!(erc.safe_transfer_from(alice(), bob(), 1, 5, vec![]).is_ok());
            assert_eq!(erc.balance_of(alice(), 1), 5);
            assert_eq!(erc.balance_of(bob(), 1), 15);

            assert!(erc.safe_transfer_from(alice(), bob(), 2, 5, vec![]).is_ok());
            assert_eq!(erc.balance_of(alice(), 2), 15);
            assert_eq!(erc.balance_of(bob(), 2), 5);
        }

        #[ink::test]
        fn sending_too_many_tokens_fails() {
            let mut erc = init_contract();
            let res = erc.safe_transfer_from(alice(), bob(), 1, 99, vec![]);
            assert_eq!(res.unwrap_err(), Error::InsufficientBalance);
        }

        #[ink::test]
        fn sending_tokens_to_zero_address_fails() {
            let burn: AccountId = [0; 32].into();

            let mut erc = init_contract();
            let res = erc.safe_transfer_from(alice(), burn, 1, 10, vec![]);
            assert_eq!(res.unwrap_err(), Error::ZeroAddressTransfer);
        }

        #[ink::test]
        fn can_send_batch_tokens() {
            let mut erc = init_contract();
            assert!(erc
                .safe_batch_transfer_from(alice(), bob(), vec![1, 2], vec![5, 10], vec![])
                .is_ok());

            let balances = erc.balance_of_batch(vec![alice(), bob()], vec![1, 2]);
            assert_eq!(balances, vec![5, 10, 15, 10])
        }

        #[ink::test]
        fn rejects_batch_if_lengths_dont_match() {
            let mut erc = init_contract();
            let res = erc.safe_batch_transfer_from(alice(), bob(), vec![1, 2, 3], vec![5], vec![]);
            assert_eq!(res.unwrap_err(), Error::BatchTransferMismatch);
        }

        #[ink::test]
        fn batch_transfers_fail_if_len_is_zero() {
            let mut erc = init_contract();
            let res = erc.safe_batch_transfer_from(alice(), bob(), vec![], vec![], vec![]);
            assert_eq!(res.unwrap_err(), Error::BatchTransferMismatch);
        }

        #[ink::test]
        fn operator_can_send_tokens() {
            let mut erc = init_contract();

            let owner = alice();
            let operator = bob();

            set_sender(owner);
            assert!(erc.set_approval_for_all(operator, true).is_ok());

            set_sender(operator);
            assert!(erc
                .safe_transfer_from(owner, charlie(), 1, 5, vec![])
                .is_ok());
            assert_eq!(erc.balance_of(alice(), 1), 5);
            assert_eq!(erc.balance_of(charlie(), 1), 5);
        }

        #[ink::test]
        fn approvals_work() {
            let mut erc = init_contract();
            let owner = alice();
            let operator = bob();
            let another_operator = charlie();

            // Note: All of these tests are from the context of the owner who is either allowing or
            // disallowing an operator to control their funds.
            set_sender(owner);
            assert!(!erc.is_approved_for_all(owner, operator));

            assert!(erc.set_approval_for_all(operator, true).is_ok());
            assert!(erc.is_approved_for_all(owner, operator));

            assert!(erc.set_approval_for_all(another_operator, true).is_ok());
            assert!(erc.is_approved_for_all(owner, another_operator));

            assert!(erc.set_approval_for_all(operator, false).is_ok());
            assert!(!erc.is_approved_for_all(owner, operator));
        }

        #[ink::test]
        fn minting_tokens_works() {
            let mut erc = HexSpace::new();

            set_sender(alice());
            assert_eq!(erc.create(0), 1);
            assert_eq!(erc.balance_of(alice(), 1), 0);

            assert!(erc.mint(1, 123).is_ok());
            assert_eq!(erc.balance_of(alice(), 1), 123);
        }

        #[ink::test]
        fn minting_not_allowed_for_nonexistent_tokens() {
            let mut erc = HexSpace::new();

            let res = erc.mint(1, 123);
            assert_eq!(res.unwrap_err(), Error::UnexistentToken);
        }

        fn assert_transfer_single_event(
            event: &ink_env::test::EmittedEvent,
            expected_operator: Option<AccountId>,
            expected_from: Option<AccountId>,
            expected_to: Option<AccountId>,
            expected_token_id: TokenId,
            expected_value: Balance,
        ) {
            let decoded_event = <Event as scale::Decode>::decode(&mut &event.data[..])
                .expect("encountered invalid contract event data buffer");
            if let Event::TransferSingle(TransferSingle {
                operator,
                from,
                to,
                token_id,
                value,
            }) = decoded_event
            {
                assert_eq!(
                    operator, expected_operator,
                    "encountered invalid TransferSingle.operator"
                );
                assert_eq!(
                    from, expected_from,
                    "encountered invalid TransferSingle.from"
                );
                assert_eq!(to, expected_to, "encountered invalid TransferSingle.to");
                assert_eq!(
                    token_id, expected_token_id,
                    "encountered invalid TransferSingle.token_id"
                );
                assert_eq!(
                    value, expected_value,
                    "encountered invalid TransferSingle.value"
                );
            } else {
                panic!("encountered unexpected event kind: expected a TransferSingle event")
            }
            let expected_topics = vec![
                encoded_into_hash(&PrefixedValue {
                    value: b"HexSpace::TransferSingle",
                    prefix: b"",
                }),
                encoded_into_hash(&PrefixedValue {
                    prefix: b"HexSpace::TransferSingle::operator",
                    value: &expected_operator,
                }),
                encoded_into_hash(&PrefixedValue {
                    prefix: b"HexSpace::TransferSingle::from",
                    value: &expected_from,
                }),
                encoded_into_hash(&PrefixedValue {
                    prefix: b"HexSpace::TransferSingle::to",
                    value: &expected_to,
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

        fn assert_transfer_batch_event(
            event: &ink_env::test::EmittedEvent,
            expected_operator: Option<AccountId>,
            expected_from: Option<AccountId>,
            expected_to: Option<AccountId>,
            expected_token_ids: Vec<TokenId>,
            expected_values: Vec<Balance>,
        ) {
            let decoded_event = <Event as scale::Decode>::decode(&mut &event.data[..])
                .expect("encountered invalid contract event data buffer");
            if let Event::TransferBatch(TransferBatch {
                operator,
                from,
                to,
                token_ids,
                values,
            }) = decoded_event
            {
                assert_eq!(
                    operator, expected_operator,
                    "encountered invalid TransferBatch.operator"
                );
                assert_eq!(
                    from, expected_from,
                    "encountered invalid TransferBatch.from"
                );
                assert_eq!(to, expected_to, "encountered invalid TransferBatch.to");
                assert_eq!(
                    token_ids, expected_token_ids,
                    "encountered invalid TransferBatch.token_ids"
                );
                assert_eq!(
                    values, expected_values,
                    "encountered invalid TransferBatch.values"
                );
            } else {
                panic!("encountered unexpected event kind: expected a TransferBatch event")
            }
            let expected_topics = vec![
                encoded_into_hash(&PrefixedValue {
                    value: b"HexSpace::TransferBatch",
                    prefix: b"",
                }),
                encoded_into_hash(&PrefixedValue {
                    prefix: b"HexSpace::TransferBatch::operator",
                    value: &expected_operator,
                }),
                encoded_into_hash(&PrefixedValue {
                    prefix: b"HexSpace::TransferBatch::from",
                    value: &expected_from,
                }),
                encoded_into_hash(&PrefixedValue {
                    prefix: b"HexSpace::TransferBatch::to",
                    value: &expected_to,
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

        #[ink::test]
        fn minting_to_tokens_works() {
            let mut erc = HexSpace::new();

            set_sender(alice());

            assert!(erc.mint_to(bob(), 1, 123).is_ok());
            assert_eq!(erc.balance_of(bob(), 1), 123);
            let emitted_events = ink_env::test::recorded_events().collect::<Vec<_>>();
            assert_eq!(emitted_events.len(), 1);
            assert_transfer_single_event(
                &emitted_events[0],
                Some(alice()),
                None,
                Some(bob()),
                1,
                123,
            );
        }
        #[ink::test]
        fn can_mint_batch_tokens() {
            let mut erc = init_contract();
            assert!(erc.mint_to_batch(bob(), vec![1, 2], vec![5, 10]).is_ok());

            let balances = erc.balance_of_batch(vec![bob()], vec![1, 2]);
            assert_eq!(balances, vec![5, 10]);
            let emitted_events = ink_env::test::recorded_events().collect::<Vec<_>>();
            assert_eq!(emitted_events.len(), 1);
            assert_transfer_batch_event(
                &emitted_events[0],
                Some(alice()),
                None,
                Some(bob()),
                vec![1, 2],
                vec![5, 10],
            );
        }

        #[ink::test]
        fn burning_to_tokens_works() {
            let mut erc = HexSpace::new();

            set_sender(alice());
            erc.balances.insert((bob(), 1), &123);
            erc.approvals.insert(&(bob(), alice()), &());
            assert!(erc.burn(bob(), 1, 123).is_ok());
            assert_eq!(erc.balance_of(bob(), 1), 0);
            let emitted_events = ink_env::test::recorded_events().collect::<Vec<_>>();
            assert_eq!(emitted_events.len(), 1);
            assert_transfer_single_event(
                &emitted_events[0],
                Some(alice()),
                Some(bob()),
                None,
                1,
                123,
            );
        }
        #[ink::test]
        fn can_burn_batch_tokens() {
            let mut erc = init_contract();
            erc.balances.insert((bob(), 1), &5);
            erc.balances.insert((bob(), 2), &10);
            erc.approvals.insert(&(bob(), alice()), &());
            // assert_eq!(erc.burn_batch(bob(), vec![1, 2], vec![5, 10]).unwrap_err(),Error::TransactionFailed);
            assert!(erc.burn_batch(bob(), vec![1, 2], vec![5, 10]).is_ok());
            let balances = erc.balance_of_batch(vec![bob()], vec![1, 2]);
            assert_eq!(balances, vec![0, 0]);
            let emitted_events = ink_env::test::recorded_events().collect::<Vec<_>>();
            assert_eq!(emitted_events.len(), 1);
            assert_transfer_batch_event(
                &emitted_events[0],
                Some(alice()),
                Some(bob()),
                None,
                vec![1, 2],
                vec![5, 10],
            );
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
