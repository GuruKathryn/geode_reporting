/*
ABOUT THIS CONTRACT...
This contract offers a way for users to report suspicious and illegal activity
across accounts and apps on the Geode Blockchain Network, and to let law enforcement 
entities into the system to act on illegal activity.
*/

#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[ink::contract]
mod geode_reporting {

    use ink::prelude::vec::Vec;
    use ink::storage::Mapping;
    use ink::storage::StorageVec;
    use ink::env::hash::{Sha2x256, HashOutput};

    // PRELIMINARY DATA STRUCTURES >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

    #[derive(Clone, Debug, PartialEq, Eq)]
    #[ink::scale_derive(Encode, Decode, TypeInfo)]
    #[cfg_attr(feature = "std",derive(ink::storage::traits::StorageLayout,))]
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
            Report {
                report_id: Hash::default(),
                reporter_account: AccountId::from([0x0; 32]),
                reporter_legal_name: <Vec<u8>>::default(),
                reporter_phone: <Vec<u8>>::default(),
                accused_account: AccountId::from([0x0; 32]),
                geode_apps: <Vec<u8>>::default(),
                activity_id_list: <Vec<u8>>::default(),
                crime_category: <Vec<u8>>::default(),
                crime_description: <Vec<u8>>::default(),
                accused_location: <Vec<u8>>::default(),
                timestamp: u64::default(),
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    #[ink::scale_derive(Encode, Decode, TypeInfo)]
    #[cfg_attr(feature = "std",derive(ink::storage::traits::StorageLayout,))]
    pub struct UserDetails {
        user_acct: AccountId,
        name: Vec<u8>,
        organization: Vec<u8>,
        phone: Vec<u8>,
        email: Vec<u8>,
    }

    impl Default for UserDetails {
        fn default() -> UserDetails {
            UserDetails {
                user_acct: AccountId::from([0x0; 32]),
                name: <Vec<u8>>::default(),
                organization: <Vec<u8>>::default(),
                phone: <Vec<u8>>::default(),
                email: <Vec<u8>>::default(),
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    #[ink::scale_derive(Encode, Decode, TypeInfo)]
    #[cfg_attr(feature = "std",derive(ink::storage::traits::StorageLayout,))]
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

    #[ink(event)]
    // writes a new report to the chain. 
    pub struct NewSAReport {
        report_id: Hash,
        #[ink(topic)]
        reporter_account: AccountId,
        #[ink(topic)]
        accused_account: AccountId,
        geode_apps: Vec<u8>,
        activity_id_list: Vec<u8>,
        crime_category: Vec<u8>,
        #[ink(topic)]
        accused_location: Vec<u8>,
        timestamp: u64,
    }


    // ERROR DEFINITIONS >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

    // Errors that can occur upon calling this contract
    #[derive(Debug, PartialEq, Eq)]
    #[ink::scale_derive(Encode, Decode, TypeInfo)]
    pub enum Error {
        // trying to report twice in 24 hours
        CannotReportAgainWithin24Hours,
        // generic error
        GenericError,
        // Data to large
        DataTooLarge,
    }


    // ACTUAL CONTRACT STORAGE >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
    #[ink(storage)]
    pub struct ContractStorage {
        account_timer: Mapping<AccountId, u64>,
        all_reports: Vec<Hash>,
        report_details: Mapping<Hash, Report>,
        allowed_entities: Mapping<AccountId, AccountId>,
        geode_legal_delegates: Mapping<AccountId, AccountId>,
        geode_legal: AccountId,
        geodelegalset: u8,
        allowed_user_map: Mapping<AccountId, UserDetails>,
        entities_vec: StorageVec<AccountId>,
        delegates_vec: StorageVec<AccountId>,
    }

    // CONTRACT LOGIC >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

    impl ContractStorage {
        
        // CONSTRUCTORS >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
        // Constructors are implicitly payable when the contract is instantiated.

        #[ink(constructor)]
        pub fn new() -> Self {
            Self {
                account_timer: Mapping::default(),
                all_reports: <Vec<Hash>>::default(),
                report_details: Mapping::default(),
                allowed_entities: Mapping::default(),
                geode_legal_delegates: Mapping::default(),
                geode_legal: AccountId::from([0x0; 32]),
                geodelegalset: 0,
                allowed_user_map: Mapping::default(),
                entities_vec: StorageVec::default(),
                delegates_vec: StorageVec::default(),
            }
        }


        // >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
        // MESSGE FUNCTIONS THAT ALTER CONTRACT STORAGE >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
        // >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
        
        // 0 🟢 MAKE A REPORT (ANYONE)
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
            let time_since_last_report = self.env().block_timestamp().wrapping_sub(timer);
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
                    geode_apps: geode_apps_where_this_happened.clone(),
                    activity_id_list: activity_clone.clone(),
                    crime_category: crime_category.clone(),
                    crime_description: crime_description,
                    accused_location: accused_user_location.clone(),
                    timestamp: new_timestamp,
                };
                // update contract storage
                // if all_reports is full, keep only the 490 most recent hashes
                if self.all_reports.len() < 490 {
                    // all is well
                }
                else {
                    // if all_reports hits 490, remove the oldest report.
                    let oldest_id = self.all_reports[0];
                    self.all_reports.remove(0);
                    self.report_details.remove(oldest_id);
                }
                // add the report id to the vector of all_reports
                self.all_reports.push(new_report_id);
                // add the details to the report_details mapping
                if self.report_details.try_insert(&new_report_id, &new_report).is_err() {
                    return Err(Error::DataTooLarge);
                }
                
                self.account_timer.insert(&caller, &new_timestamp);

                // Emit an event to register the report to the chain
                Self::env().emit_event(NewSAReport {
                    report_id: new_report_id,
                    reporter_account: caller,
                    accused_account: accused_account,
                    geode_apps: geode_apps_where_this_happened,
                    activity_id_list: activity_clone,
                    crime_category: crime_category,
                    accused_location: accused_user_location,
                    timestamp: new_timestamp,
                });
                
                Ok(())
            }
            
        }


        // 1 🟢 SET GEODE LEGAL ROOT ACCOUNT
        // This message lets us set the root geode legal account one time, in the beginning
        #[ink(message)]
        pub fn set_geode_legal_root(&mut self, 
            new_geode_legal_root: AccountId,
            name: Vec<u8>,
            organization: Vec<u8>,
            phone: Vec<u8>,
            email: Vec<u8>,
        ) -> Result<(), Error> {
            let caller = Self::env().caller();
            // check that the Geode Legal root user is not yet set
            if self.geodelegalset != 1 || self.geode_legal == caller {
                // proceed to set up the root user
                self.geode_legal = new_geode_legal_root;
                self.geodelegalset = 1;

                // add the root user to the delegates team
                if self.geode_legal_delegates.contains(&new_geode_legal_root) {
                    // do nothing
                }
                else {
                    // add the new root to the delegates list
                    self.geode_legal_delegates.insert(&new_geode_legal_root, &new_geode_legal_root);
                    // and to the delegates_vec
                    self.delegates_vec.push(&new_geode_legal_root);
                }
                
                // add the new root or update their info in the allowed_user_map
                let new_user = UserDetails {
                    user_acct: new_geode_legal_root,
                    name: name,
                    organization: organization,
                    phone: phone,
                    email: email,
                };
                if self.allowed_user_map.try_insert(&new_geode_legal_root, &new_user).is_err() {
                    return Err(Error::DataTooLarge);
                }        

            }
            else {
                // if the geode legal root user has already been set 
                // and the caller is not that root user, send an error
                return Err(Error::GenericError)
            }
            Ok(())
        }


        // 2 🟢 ADD GEODE LEGAL DELEGATE (RESTRICTED: GEODE LEGAL ROOT ONLY)
        // This message lets the Geode Legal root add accounts to the legal team 
        #[ink(message)]
        pub fn add_geode_legal_delegate(&mut self, 
            add: AccountId,
            name: Vec<u8>,
            organization: Vec<u8>,
            phone: Vec<u8>,
            email: Vec<u8>,
        ) -> Result<(), Error> {
            // check that the caller is the Geode Legal root account
            let caller = Self::env().caller();
            if self.geode_legal == caller {
                // if the new delegate is already in the delegates vector,
                // skip to updating their contact info
                if self.geode_legal_delegates.contains(&add) {
                    // do nothing
                }
                else {
                    // add the new root to the delegates list
                    self.geode_legal_delegates.insert(&add, &add);
                    // and to the delegates_vec
                    self.delegates_vec.push(&add);
                }
                // add or update the contact info to the allowed_user_map
                let new_user = UserDetails {
                    user_acct: add,
                    name: name,
                    organization: organization,
                    phone: phone,
                    email: email,
                };
                if self.allowed_user_map.try_insert(&add, &new_user).is_err() {
                    return Err(Error::DataTooLarge);
                }        
            }
            else {
                // error: this account is not allowed to take this action
                return Err(Error::GenericError)
            }
            Ok(())
        }


        // 3 🟢 REMOVE GEODE LEGAL DELEGATE (RESTRICTED: GEODE LEGAL ROOT ONLY)
        // This message lets Geode Legal root account remove accounts from the legal team 
        #[ink(message)]
        pub fn remove_geode_legal_delegate(&mut self, remove: AccountId) -> Result<(), Error> {
            // check that the caller is the root user
            let caller = Self::env().caller();
            if self.geode_legal == caller {
                // if so, remove the delegate from geode_legal_delegates
                if self.geode_legal_delegates.contains(remove) {
                    self.geode_legal_delegates.remove(remove);
                }
                // remove the delegate from allowed_user_map
                if self.allowed_user_map.contains(remove) {
                    self.allowed_user_map.remove(remove);
                }
            }
            // if the caller is not the root user, return fail
            else {
                // error
                return Err(Error::GenericError)
            }
            Ok(())
        }


        // 4 🟢 ALLOW A LAW ENFORCEMENT ENTITY TO HAVE ACCESS (RESTRICTED: GEODE LEGAL OR DELEGATE)
        // This message allows the Geode Legal team to give access to law enforcement entities
        #[ink(message)]
        pub fn add_law_enforcement_access(&mut self, 
            add: AccountId,
            name: Vec<u8>,
            organization: Vec<u8>,
            phone: Vec<u8>,
            email: Vec<u8>,
        ) -> Result<(), Error> {
            // check that the caller is on the delegates list
            let caller = Self::env().caller();
            if self.geode_legal_delegates.contains(&caller) {
                // if the new entity is already in the allowed_entities vector...
                if self.allowed_entities.contains(&add) {
                    // do nothing
                }
                else {
                    // add the new entity to the allowed_entities list
                    self.allowed_entities.insert(&add, &add);
                    // and to the entities_vec
                    self.entities_vec.push(&add);
                    
                }
                // add or update the new entity in the allowed_user_map
                let new_user = UserDetails {
                    user_acct: add,
                    name: name,
                    organization: organization,
                    phone: phone,
                    email: email,
                };
                if self.allowed_user_map.try_insert(&add, &new_user).is_err() {
                    return Err(Error::DataTooLarge);
                }        

            }
            else {
                // error
                return Err(Error::GenericError)
            }
            Ok(())
        }


        // 5 🟢 REMOVE A LAW ENFORCEMENT ENTITY'S ACCESS (RESTRICTED: GEODE LEGAL OR DELEGATE)
        #[ink(message)]
        pub fn remove_law_enforcement_access(&mut self, remove: AccountId) -> Result<(), Error> {
            // check that the caller is on the delegates list
            let caller = Self::env().caller();
            if self.geode_legal_delegates.contains(&caller) {
                // if so, remove the user from allowed_entities
                if self.allowed_entities.contains(remove) {
                    self.allowed_entities.remove(remove);
                }
                // remove them from allowed_user_map
                if self.allowed_user_map.contains(remove) {
                    self.allowed_user_map.remove(remove);
                }
            }
            // if not, return fail
            else {
                // error
                return Err(Error::GenericError)
            }
            Ok(())
        }


        // >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
        // MESSAGE FUNCTIONS THAT RETRIEVE DATA FROM STORAGE  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
        // >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

        // 6 🟢 VIEW ALL REPORTS (RESTRICTED: GEODE LEGAL OR DELEGATE OR ALLOWED ENTITIY)
        // this message is restricted to two types of users...
        // Geode Legal - a single account in charge of SAR information requests and its delegates
        // Law Enforcement Entities - verified entities that can be given permission
        // to view reports by the Geode Legal account.
        #[ink(message)]
        pub fn view_all_reports(&self) -> Vec<Report> {
            let caller = Self::env().caller();
            // set up return structure
            let mut allreports: Vec<Report> = Vec::new();
            // check that the caller is on one of the allowed lists
            if self.allowed_entities.contains(&caller) || self.geode_legal_delegates.contains(&caller) {
                // iterate through the report hashes in all_reports to get the details of each
                for id in self.all_reports.iter() {
                    let details = self.report_details.get(id).unwrap_or_default();
                    allreports.push(details);
                }
            }
            // return results
            allreports
        }

        // 7 🟢 VIEW LEGAL TEAM & ALLOWED ENTITIES (RESTRICTED: GEODE LEGAL OR DELEGATE)
        #[ink(message)]
        pub fn view_allowed_delegates_and_entities(&self) -> ViewAllowed {
            // set up the return structures
            let mut all_delegates: Vec<UserDetails> = Vec::new();
            let mut all_entities: Vec<UserDetails> = Vec::new();

            // check that the caller is on the delegates list
            let caller = Self::env().caller();
            if self.geode_legal_delegates.contains(&caller) {
                // for each account in geode_legal_delegates...
                if self.delegates_vec.len() > 0 {
                    for i in 0..self.delegates_vec.len() {
                        // get the profile for the account
                        let acct = self.delegates_vec.get(i).unwrap();
                        if self.geode_legal_delegates.contains(&acct) {
                            // get the UserDetails from allowed_user_map
                            let details = self.allowed_user_map.get(&acct).unwrap_or_default();
                            // add it to all_delegates
                            all_delegates.push(details);
                        }
                        
                    }
                }

                // for each account in allowed_entities...
                if self.entities_vec.len() > 0 {
                    for i in 0..self.entities_vec.len() {
                        // get the profile for the account
                        let acct = self.entities_vec.get(i).unwrap();
                        if self.allowed_entities.contains(&acct) {
                            // get the UserDetails from allowed_user_map
                            let details = self.allowed_user_map.get(&acct).unwrap_or_default();
                            // add it to all_entities
                            all_entities.push(details);
                        }
                    }
                }
            }

            // package the results
            let results = ViewAllowed {
                delegates: all_delegates,
                entities: all_entities,
            };
            // return results
            results
        }

        // END OF MESSAGE FUNCTIONS

    }
    // END OF CONTRACT LOGIC

}
