/*
ABOUT THIS CONTRACT...
This contract offers a way for users to report suspicious and illegal activity
across accounts and apps on the Geode Blockchain Network.
*/

#![cfg_attr(not(feature = "std"), no_std)]

#[ink::contract]
mod geode_suspicious_activity_reporting {

    use ink::prelude::vec::Vec;
    use ink::storage::Mapping;
    use ink::env::hash::{Sha2x256, HashOutput};

    // PRELIMINARY DATA STRUCTURES >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

    #[derive(Clone, scale::Decode, scale::Encode)]
    #[cfg_attr(
        feature = "std",
        derive(
            ink::storage::traits::StorageLayout, 
            scale_info::TypeInfo,
            Debug,
            PartialEq,
            Eq
        )
    )]
    pub struct Report {
        report_id: Hash,
        reporter_account: AccountId,
        reporter_legal_name: Vec<u8>,
        reporter_phone: Vec<u8>,
        accused_account: AccountId,
        geode_apps: Vec<u8>,
        activity_id_list: Vec<u8>,
        crime_category: Vec<u8>,
        crime_description: Vec<u8>,
        accused_location: Vec<u8>,
        timestamp: u64,
    }
    
    impl Default for Report {
        fn default() -> Report {
            let default_addy = "000000000000000000000000000000000000000000000000";
            let default_addy_id32: AccountId = default_addy.as_bytes().try_into().unwrap();
            Report {
                report_id: Hash::default(),
                reporter_account: default_addy_id32,
                reporter_legal_name: <Vec<u8>>::default(),
                reporter_phone: <Vec<u8>>::default(),
                accused_account: default_addy_id32,
                geode_apps: <Vec<u8>>::default(),
                activity_id_list: <Vec<u8>>::default(),
                crime_category: <Vec<u8>>::default(),
                crime_description: <Vec<u8>>::default(),
                accused_location: <Vec<u8>>::default(),
                timestamp: u64::default(),
            }
        }
    }

    #[derive(Clone, scale::Decode, scale::Encode)]
    #[cfg_attr(
        feature = "std",
        derive(
            ink::storage::traits::StorageLayout, 
            scale_info::TypeInfo,
            Debug,
            PartialEq,
            Eq
        )
    )]
    pub struct UserDetails {
        user_acct: AccountId,
        name: Vec<u8>,
        organization: Vec<u8>,
        phone: Vec<u8>,
        email: Vec<u8>,
    }

    impl Default for UserDetails {
        fn default() -> UserDetails {
            let default_addy = "000000000000000000000000000000000000000000000000";
            let default_addy_id32: AccountId = default_addy.as_bytes().try_into().unwrap();
            UserDetails {
                user_acct: default_addy_id32,
                name: <Vec<u8>>::default(),
                organization: <Vec<u8>>::default(),
                phone: <Vec<u8>>::default(),
                email: <Vec<u8>>::default(),
            }
        }
    }

    #[derive(Clone, scale::Decode, scale::Encode)]
    #[cfg_attr(
        feature = "std",
        derive(
            ink::storage::traits::StorageLayout, 
            scale_info::TypeInfo,
            Debug,
            PartialEq,
            Eq
        )
    )]
    pub struct ViewAllowed {
        delegates: Vec<UserDetails>,
        entities: Vec<UserDetails>,
    }

    impl Default for ViewAllowed {
        fn default() -> ViewAllowed {
            ViewAllowed {
                delegates: <Vec<UserDetails>>::default(),
                entities: <Vec<UserDetails>>::default(),
            }
        }
    }


    // EVENT DEFINITIONS >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
    // no events will be written to the chain. 


    // ERROR DEFINITIONS >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

    // Errors that can occur upon calling this contract
    #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(::scale_info::TypeInfo))]
    pub enum Error {
        // trying to report twice in 24 hours
        CannotReportAgainWithin24Hours,
    }

    // ACTUAL CONTRACT STORAGE >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
    #[ink(storage)]
    pub struct ContractStorage {
        account_timer: Mapping<AccountId, u64>,
        reports: Vec<Report>,
        allowed_entities: Vec<AccountId>,
        geode_legal_delegates: Vec<AccountId>,
        geode_legal: AccountId,
        geodelegalset: u8,
        allowed_user_map: Mapping<AccountId, UserDetails>,
    }

    // CONTRACT LOGIC >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

    impl ContractStorage {
        
        // CONSTRUCTORS >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
        // Constructors are implicitly payable when the contract is instantiated.

        #[ink(constructor)]
        pub fn new() -> Self {
            let default_addy = "000000000000000000000000000000000000000000000000";
            let default_addy_id32: AccountId = default_addy.as_bytes().try_into().unwrap();
            Self {
                account_timer: Mapping::default(),
                reports: <Vec<Report>>::default(),
                allowed_entities: <Vec<AccountId>>::default(),
                geode_legal_delegates: <Vec<AccountId>>::default(),
                geode_legal: default_addy_id32,
                geodelegalset: u8::default(),
                allowed_user_map: Mapping::default(),
            }
        }

        // MESSGE FUNCTIONS THAT ALTER CONTRACT STORAGE >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
        
        // 🟢 MAKE A REPORT (ANYONE)
        #[ink(message)]
        pub fn make_a_report(&mut self, 
            your_legal_name: Vec<u8>,
            your_phone: Vec<u8>,
            accused_account: AccountId,
            geode_apps_where_this_happened: Vec<u8>,
            activity_id_list: Vec<u8>,
            crime_category: Vec<u8>,
            crime_description: Vec<u8>,
            accused_user_location: Vec<u8>,
        ) -> Result<(), Error> {

            let caller = Self::env().caller();

            // check that caller has not made a report in the last 24 hours
            let timer = self.account_timer.get(&caller).unwrap_or_default();
            let time_since_last_report = self.env().block_timestamp() - timer;
            if time_since_last_report < 86400000 {
                // send an error that interest cannot be updated so soon
                return Err(Error::CannotReportAgainWithin24Hours)
            }

            else {
                // proceed to make the report
                // set up clones as needed
                let activity_clone = activity_id_list.clone();

                // set up the data that will go into the new_report_id hash
                let new_timestamp = self.env().block_timestamp();
                // create the new_report_id by hashing the above data
                let encodable = (caller, accused_account, activity_id_list, new_timestamp); // Implements `scale::Encode`
                let mut new_report_id_u8 = <Sha2x256 as HashOutput>::Type::default(); // 256-bit buffer
                ink::env::hash_encoded::<Sha2x256, _>(&encodable, &mut new_report_id_u8);
                let new_report_id: Hash = Hash::from(new_report_id_u8);

                // set up the report details
                let new_report = Report {
                    report_id: new_report_id,
                    reporter_account: caller,
                    reporter_legal_name: your_legal_name,
                    reporter_phone: your_phone,
                    accused_account: accused_account,
                    geode_apps: geode_apps_where_this_happened,
                    activity_id_list: activity_clone,
                    crime_category: crime_category,
                    crime_description: crime_description,
                    accused_location: accused_user_location,
                    timestamp: new_timestamp,
                };
                // update contract storage
                self.reports.push(new_report);
                self.account_timer.insert(&caller, &new_timestamp);
                
                Ok(())
            }
            
        }


        // MESSAGE FUNCTIONS THAT RETRIEVE DATA FROM STORAGE  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

        // 🟢 VIEW ALL REPORTS (RESTRICTED: GEODE LEGAL OR DELEGATE OR ALLOWED ENTITIY)
        // this message is restricted to two types of users...
        // Geode Legal - a single account in charge of SAR information requests
        // Law Enforcement Entities - verified entities that can be given permission
        // to view reports by the Geode Legal account.
        #[ink(message)]
        pub fn view_all_reports(&self) -> Vec<Report> {
            let caller = Self::env().caller();
            // check that the caller is on one of the allowed lists
            if self.allowed_entities.contains(&caller) || self.geode_legal_delegates.contains(&caller) {
                // proceed...
                let allreports = self.reports.clone();
                allreports
            }
            else {
                let allreports = <Vec<Report>>::default();
                allreports
            }
        }

        // 🟢 SET GEODE LEGAL ROOT ACCOUNT
        // This message lets us set the root geode legal account one time, in the beginning
        #[ink(message)]
        pub fn set_geode_legal_root(&mut self, 
            new_geode_legal_root: AccountId,
            name: Vec<u8>,
            organization: Vec<u8>,
            phone: Vec<u8>,
            email: Vec<u8>,
        ) -> u8 {
            let caller = Self::env().caller();
            // check that the Geode Legal root user is not yet set
            if self.geodelegalset != 1 {
                // proceed to set up the root user for the first time
                self.geode_legal = new_geode_legal_root;
                self.geodelegalset = 1;
                // add the root user to the delegates team
                // if the new root is already in the vector, do nothing
                if self.geode_legal_delegates.contains(&new_geode_legal_root) {
                    // do nothing
                }
                else {
                    // add the new root to the delegates list
                    self.geode_legal_delegates.push(new_geode_legal_root);
                    // add the new root to the allowed_user_map
                    let new_user = UserDetails {
                        user_acct: new_geode_legal_root,
                        name: name,
                        organization: organization,
                        phone: phone,
                        email: email,
                    };
                    self.allowed_user_map.insert(&new_geode_legal_root, &new_user);
                }
                let success: u8 = 1;
                success
            }
            else {
                // if the geode legal root user has already been set, 
                // make sure the caller is that root user
                if self.geode_legal == caller {
                    // proceed to update the geode legal root user
                    self.geode_legal = new_geode_legal_root;
                    // add the root user to the delegates team
                    // if the new root is already in the vector, do nothing
                    if self.geode_legal_delegates.contains(&new_geode_legal_root) {
                        // do nothing
                    }
                    else {
                        // add the new root to the delegates list
                        self.geode_legal_delegates.push(new_geode_legal_root);
                        // add the new root to the allowed_user_map
                        let new_user = UserDetails {
                            user_acct: new_geode_legal_root,
                            name: name,
                            organization: organization,
                            phone: phone,
                            email: email,
                        };
                        self.allowed_user_map.insert(&new_geode_legal_root, &new_user);
                    }
                    let success: u8 = 2;
                    success
                }
                else {
                    // if the root is set, and the caller is not the root
                    let fail: u8 = 0;
                    fail
                }
            }
        }


        // 🟢 ADD GEODE LEGAL DELEGATE (RESTRICTED: GEODE LEGAL OR DELEGATE)
        // This message lets Geode Legal team accounts add accounts to the legal team 
        #[ink(message)]
        pub fn add_geode_legal_delegate(&mut self, 
            add: AccountId,
            name: Vec<u8>,
            organization: Vec<u8>,
            phone: Vec<u8>,
            email: Vec<u8>,
        ) -> u8 {
            // check that the caller is on the delegates list
            let caller = Self::env().caller();
            if self.geode_legal_delegates.contains(&caller) {
                // if the new delegate is already in the delegates vector, do nothing
                if self.geode_legal_delegates.contains(&add) {
                    // do nothing
                }
                else {
                    // add the new delegate to the delegates list
                    self.geode_legal_delegates.push(add);
                    // add the new root to the allowed_user_map
                    let new_user = UserDetails {
                        user_acct: add,
                        name: name,
                        organization: organization,
                        phone: phone,
                        email: email,
                    };
                    self.allowed_user_map.insert(&add, &new_user);
                }
                // report success
                let success: u8 = 1;
                success
            }
            else {
                // return fail
                let fail: u8 = 0;
                fail
            }
        }

        // 🟢 REMOVE GEODE LEGAL DELEGATE (RESTRICTED: GEODE LEGAL OR DELEGATE)
        // This message lets Geode Legal team accounts remove accounts from the legal team 
        #[ink(message)]
        pub fn remove_geode_legal_delegate(&mut self, remove: AccountId) -> u8 {
            // check that the caller is on the delegates list
            let caller = Self::env().caller();
            if self.geode_legal_delegates.contains(&caller) {
                // if so, remove the delegate from geode_legal_delegates
                self.geode_legal_delegates.retain(|value| *value != remove);
                // remove them from allowed_user_map
                self.allowed_user_map.remove(remove);
                // report success
                let success: u8 = 1;
                success
            }
            // if not, return fail
            else {
                let fail: u8 = 0;
                fail
            }
        }


        // 🟢 ALLOW A LAW ENFORCEMENT ENTITY TO HAVE ACCESS (RESTRICTED: GEODE LEGAL OR DELEGATE)
        // This message allows the Geode Legal team to give access to law enforcement entities
        #[ink(message)]
        pub fn add_law_enforcement_access(&mut self, 
            add: AccountId,
            name: Vec<u8>,
            organization: Vec<u8>,
            phone: Vec<u8>,
            email: Vec<u8>,
        ) -> u8 {
            // check that the caller is on the delegates list
            let caller = Self::env().caller();
            if self.geode_legal_delegates.contains(&caller) {
                // if the new entity is already in the allowed_entities vector...
                if self.allowed_entities.contains(&add) {
                    // do nothing
                }
                else {
                    // add the new delegate to the allowed_entities list
                    self.allowed_entities.push(add);
                    // add the new root to the allowed_user_map
                    let new_user = UserDetails {
                        user_acct: add,
                        name: name,
                        organization: organization,
                        phone: phone,
                        email: email,
                    };
                    self.allowed_user_map.insert(&add, &new_user);
                }
                // report success
                let success: u8 = 1;
                success
            }
            else {
                // return fail
                let fail: u8 = 0;
                fail
            }
        }


        // 🟢 REMOVE A LAW ENFORCEMENT ENTITY'S ACCESS (RESTRICTED: GEODE LEGAL OR DELEGATE)
        #[ink(message)]
        pub fn remove_law_enforcement_access(&mut self, remove: AccountId) -> u8 {
            // check that the caller is on the delegates list
            let caller = Self::env().caller();
            if self.geode_legal_delegates.contains(&caller) {
                // if so, remove the user from allowed_entities
                self.allowed_entities.retain(|value| *value != remove);
                // remove them from allowed_user_map
                self.allowed_user_map.remove(remove);
                // report success
                let success: u8 = 1;
                success
            }
            // if not, return fail
            else {
                let fail: u8 = 0;
                fail
            }
        }

        // 🟢 VIEW LEGAL TEAM & ALLOWED ENTITIES (RESTRICTED: GEODE LEGAL OR DELEGATE)
        #[ink(message)]
        pub fn view_allowed_delegates_and_entities(&self) -> ViewAllowed {
            // set up the return structures
            let mut all_delegates: Vec<UserDetails> = Vec::new();
            let mut all_entities: Vec<UserDetails> = Vec::new();

            // check that the caller is on the delegates list
            let caller = Self::env().caller();
            if self.geode_legal_delegates.contains(&caller) {
                // for each account in geode_legal_delegates
                for acct in &self.geode_legal_delegates {
                    // get the UserDetails from allowed_user_map
                    let details = self.allowed_user_map.get(&acct).unwrap_or_default();
                    // add it to all_delegates
                    all_delegates.push(details);
                }
                // for each account in allowed_entities
                for acct in &self.allowed_entities {
                    // get the UserDetails from allowed_user_map
                    let details = self.allowed_user_map.get(&acct).unwrap_or_default();
                    // add it to all_entities
                    all_entities.push(details);
                }
                // package the results
                let results = ViewAllowed {
                    delegates: all_delegates,
                    entities: all_entities,
                };
                results
            }
            // if not, return empty results
            else {
                let results = ViewAllowed {
                    delegates: <Vec<UserDetails>>::default(),
                    entities: <Vec<UserDetails>>::default(),
                };
                results
            }
        }


        // END OF MESSAGE FUNCTIONS

    }
    // END OF CONTRACT LOGIC

}
