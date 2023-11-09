// This entire file is only compiled when running tests
#![cfg(test)]
const USERNAME: &str = "muhUserName";
const PASSWORD: &str = "p@&^ssw07rd1AFE";
const NEW_PASSWORD: &str = "x@^*ssw93un1KLM";
const USERNAME2: &str = "muhSecondUser";
const PASSWORD2: &str = "p@&^ssw07rd1OPI";
const IDENTIFIER: &str = "website.com";
const PASSWORD_FEW_UPPERCASE: &str = "passwOrd@p14ass"; 
const PASSWORD_FEW_DIGITS: &str = "Passwo1d@Passdfe"; 
const PASSWORD_FEW_SYMBOLS: &str = "Passrd123456abcx"; 
const SHORT_PASSWORD: &str = "!@236azxBCX*"; 

// Assuming `PasswordManager` is in a module named `password_manager` at the root of the src directory

// use armor_pass::password_manager::PasswordManager;
use armor_pass::password_manager::PasswordManager;

fn teardown() {
    let _ = std::fs::remove_file("/tmp/armor_pass.enc");
}

#[test]
fn it_stores_a_password() {
    let mut password_manager = PasswordManager::new();
    let result = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);
    assert_eq!(result.is_ok(), true);
    assert!(password_manager.has_password(IDENTIFIER, USERNAME));
    teardown();
}


#[test]
fn it_retrieves_multiple_passwords_for_same_identifier() {
    let mut password_manager = PasswordManager::new();
    let _ = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);
    let _ = password_manager.store_password(IDENTIFIER, USERNAME2, PASSWORD2);
    let credentials = password_manager.retrieve_credentials(IDENTIFIER);
    assert_eq!(credentials.len(), 2);
    teardown();
}

#[test]
fn it_retrieves_the_correct_password() {
    let mut password_manager = PasswordManager::new();
    let _ = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);
    let _ = password_manager.store_password(IDENTIFIER, USERNAME2, PASSWORD2);

    let retrieved_password = password_manager.retrieve_password(IDENTIFIER, USERNAME);
    assert_eq!(retrieved_password, Some(PASSWORD));
    
    let retrieved_password2 = password_manager.retrieve_password(IDENTIFIER, USERNAME2);
    assert_eq!(retrieved_password2, Some(PASSWORD2));
}

#[test]
fn it_reports_successful_password_updates() {
    let mut password_manager = PasswordManager::new();
    let _ = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);
    let update_result = password_manager.update_password(IDENTIFIER, USERNAME, NEW_PASSWORD);
    assert_eq!(update_result, Ok(()), "Password update should report success.");
}
//
#[test]
fn it_really_updates_the_password() {
    let mut password_manager = PasswordManager::new();
    let _ = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);
    let _ = password_manager.update_password(IDENTIFIER, USERNAME, NEW_PASSWORD);
    let retrieved_password = password_manager.retrieve_password(IDENTIFIER, USERNAME);
    assert_eq!(retrieved_password, Some(NEW_PASSWORD), "Password should be updated to new password.");
    teardown();
}
//
#[test]
fn updating_a_particular_credential_set_does_not_affect_others() {
    let mut password_manager = PasswordManager::new();
    let _ = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);
    let _ = password_manager.store_password(IDENTIFIER, USERNAME2, PASSWORD2);
    let _ = password_manager.update_password(IDENTIFIER, USERNAME, NEW_PASSWORD);
    let retrieved_password2 = password_manager.retrieve_password(IDENTIFIER, USERNAME2);
    assert_eq!(retrieved_password2, Some(PASSWORD2), "Password for second user should remain unchanged.");
}

#[test]
fn deleting_a_particular_credential_set_does_not_affect_others() {
    let mut password_manager = PasswordManager::new();
    let _ = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);
    let _ = password_manager.store_password(IDENTIFIER, USERNAME2, PASSWORD2);
    let _ = password_manager.update_password(IDENTIFIER, USERNAME, NEW_PASSWORD);
    let retrieved_password2 = password_manager.retrieve_password(IDENTIFIER, USERNAME2);
    assert_eq!(retrieved_password2, Some(PASSWORD2), "Password for second user should remain unchanged.");
}

#[test]
fn it_reports_true_when_deleting_valid_credentials() {
    let mut password_manager = PasswordManager::new();
    let _ = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);
    let delete_result = password_manager.delete_credential(IDENTIFIER, USERNAME);
    assert_eq!(delete_result, Ok(()), "Deleting an existing password should succeed.");
}

#[test]
fn it_cannot_retrieve_a_deleted_password() {
    let mut password_manager = PasswordManager::new();
    let _ = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);

    // Delete the password and assert that deletion was successful
    let delete_result = password_manager.delete_credential(IDENTIFIER, USERNAME);
    assert_eq!(delete_result, Ok(()), "Deleting an existing password should succeed.");

    // Attempt to retrieve the deleted password
    let retrieved_password = password_manager.retrieve_password(IDENTIFIER, USERNAME);

    // Assert that the password cannot be retrieved after deletion
    assert_eq!(retrieved_password, None, "A deleted password should not be retrievable.");
}
//
// Tests that the method reports the correct status when attempting to delete a non-existent password.
#[test]
fn it_reports_failure_when_deleting_nonexistent_password() {
    let mut password_manager = PasswordManager::new();
    let delete_result = password_manager.delete_credential(IDENTIFIER, USERNAME);
    assert!(delete_result.is_err(), "Deleting a non-existent password should fail.");
}

// Tests that deleting one password does not affect other stored passwords.
#[test]
fn it_does_not_delete_other_passwords() {
    let mut password_manager = PasswordManager::new();
    let _ = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);
    let _ = password_manager.store_password(IDENTIFIER, USERNAME2, PASSWORD2);
    let _ = password_manager.delete_credential(IDENTIFIER, USERNAME);
    assert!(!password_manager.has_password(IDENTIFIER, USERNAME), "The specified password should be deleted.");
    assert!(password_manager.has_password(IDENTIFIER, USERNAME2), "Other passwords should not be affected by the deletion of a different one.");
}

#[test]
fn it_does_not_allow_identifiers_with_less_than_3_characters() {
    let mut password_manager = PasswordManager::new();
    let store_result = password_manager.store_password("", USERNAME, PASSWORD);
    assert!(
        store_result.is_err(),
        "Passwords should not be allowed to be stored with an empty identifier."
    );
    teardown();
}

//
#[test]
fn it_does_not_allow_empty_usernames() {
    let mut password_manager = PasswordManager::new();
    let store_result = password_manager.store_password(IDENTIFIER, "", PASSWORD);
    
    assert!(
        store_result.is_err(),
        "Passwords should not be allowed to be stored with an empty username."
    );
    teardown();
}

#[test]
fn it_does_not_allow_empty_passwords() {
    let mut password_manager = PasswordManager::new();
    let store_result = password_manager.store_password(IDENTIFIER, USERNAME, "");
    assert!(
        store_result.is_err(),
        "Passwords should not be allowed to be stored when empty."
    );
    teardown();
}
#[test]
fn it_does_not_allow_identical_passwords() {
    let mut password_manager = PasswordManager::new();
    
    // Store a password for the first time.
    let first_store_result = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);
    assert_eq!(
        first_store_result,
        Ok(()),
        "The first attempt to store a password should succeed."
    );

    // Attempt to store the same password again.
    let second_store_result = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);
    assert!(
        second_store_result.is_err(),
        "Storing an identical password for the same identifier and username should not be allowed."
    );
    teardown();
}

#[test]
fn it_does_not_allow_passwords_shorter_than_fourteen_characters() {
    let mut password_manager = PasswordManager::new();
    // Attempt to store a short password.
    let store_result = password_manager.store_password(IDENTIFIER, USERNAME, SHORT_PASSWORD);
    // Assert that storing a password with fewer than 10 characters fails.
    assert!(
        store_result.is_err(),
        "Passwords with fewer than 14 characters should not be allowed."
    );
    teardown();
}

#[test]
fn it_requires_at_least_three_uppercase_letters_in_password() {
    let mut password_manager = PasswordManager::new();
    let store_result = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD_FEW_UPPERCASE);
    assert!(
        store_result.is_err(),
        "Passwords must contain at least three uppercase letters."
    );
    teardown();
}

#[test]
fn it_requires_at_least_three_digits_in_password() {
    let mut password_manager = PasswordManager::new();
    let store_result = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD_FEW_DIGITS);
    assert!(
        store_result.is_err(),
        "Passwords must contain at least three digits."
    );
    teardown();
}

#[test]
fn it_requires_at_least_three_symbols_in_password() {
    let mut password_manager = PasswordManager::new();
    let store_result = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD_FEW_SYMBOLS);
    assert!(
        store_result.is_err(),
        "Passwords must contain at least three symbols."
    );
    teardown();
}

// #[test]
// fn test_save_and_load() {
//     let mut manager = PasswordManager::default();
//     manager.records.push(PasswordRecord {
//         identifier: "example.com".into(),
//         username: "user123".into(),
//         password: "securepassword".into(),
//     });
//
//     let file_path = Path::new("test_passwords.json");
//     
//     // Test saving
//     manager.save_to_file(file_path).unwrap();
//     assert!(file_path.exists());
//
//     // Test loading
//     let loaded_manager = PasswordManager::load_from_file(file_path).unwrap();
//     assert_eq!(loaded_manager.records, manager.records);
//
//     // Clean up
//     fs::remove_file(file_path).unwrap();
// }

