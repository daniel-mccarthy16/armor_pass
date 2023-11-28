// this entire file is only compiled when running tests
#![cfg(test)]
const USERNAME: &str = "muhusername";
const PASSWORD: &str = "p@&^ssW07Rd1Afe";
const NEW_PASSWORD: &str = "x@^*ssw93un1klm";
const USERNAME2: &str = "muhseconduser";
const PASSWORD2: &str = "P@&^ssW07rd1opI";
const IDENTIFIER: &str = "website.com";
const PASSWORD_FEW_UPPERCASE: &str = "password@p14ass";
const PASSWORD_FEW_DIGITS: &str = "passwo1d@passdfe";
const PASSWORD_FEW_SYMBOLS: &str = "passrd123456abcx";
const SHORT_PASSWORD: &str = "!@236azxbcx*";
const SALT: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
const MASTERPASSWORD: &str = "heynowbrowncowaylmao";

use armor_pass::password_manager::PasswordManager;
use std::path::PathBuf;
use uuid::Uuid;

fn teardown(filepath: &PathBuf) {
    let _ = std::fs::remove_file(filepath);
}

fn generate_unique_file_path() -> PathBuf {
    let unique_id = Uuid::new_v4().to_string();
    PathBuf::from(format!("/tmp/test_{}.enc", unique_id))
}

#[test]
fn it_stores_a_password() {
    let tmpfile = generate_unique_file_path();
    let mut password_manager = PasswordManager::new(tmpfile.clone(), MASTERPASSWORD)
        .expect("could not create password manager");
    // println!("muh {:?}", password_manager);
    let result = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);
    println!("result is X: {:?}", result);
    assert_eq!(result.is_ok(), true);
    assert!(password_manager.has_password(IDENTIFIER, USERNAME));
    teardown(&tmpfile);
}

#[test]
fn it_retrieves_multiple_passwords_for_same_identifier() {
    let tmpfile = generate_unique_file_path();
    let mut password_manager = PasswordManager::new(tmpfile.clone(), MASTERPASSWORD)
        .expect("could not create password manager");
    let _ = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);
    let _ = password_manager.store_password(IDENTIFIER, USERNAME2, PASSWORD2);
    let credentials = password_manager.retrieve_credentials(IDENTIFIER);
    assert_eq!(credentials.len(), 2);
    teardown(&tmpfile);
}

#[test]
fn it_retrieves_the_correct_password() {
    let tmpfile = generate_unique_file_path();
    let mut password_manager = PasswordManager::new(tmpfile.clone(), MASTERPASSWORD)
        .expect("could not create password manager");
    let _ = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);
    let _ = password_manager.store_password(IDENTIFIER, USERNAME2, PASSWORD2);

    let retrieved_credential = password_manager.retrieve_password(IDENTIFIER, USERNAME);
    assert_eq!(retrieved_credential.unwrap().password, PASSWORD);

    let retrieved_credential2 = password_manager.retrieve_password(IDENTIFIER, USERNAME2);
    assert_eq!(retrieved_credential2.unwrap().password, PASSWORD2);
    teardown(&tmpfile);
}

#[test]
fn it_reports_successful_password_updates() {
    let tmpfile = generate_unique_file_path();
    let mut password_manager = PasswordManager::new(tmpfile.clone(), MASTERPASSWORD)
        .expect("could not create password manager");
    let _ = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);
    let update_result = password_manager.update_password(IDENTIFIER, USERNAME, NEW_PASSWORD);
    assert_eq!(
        update_result,
        Ok(()),
        "Password update should report success."
    );
    teardown(&tmpfile);
}
//
#[test]
fn it_really_updates_the_password() {
    let tmpfile = generate_unique_file_path();
    let mut password_manager = PasswordManager::new(tmpfile.clone(), MASTERPASSWORD)
        .expect("could not create password manager");
    let _ = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);
    let _ = password_manager.update_password(IDENTIFIER, USERNAME, NEW_PASSWORD);
    let retrieved_credential = password_manager.retrieve_password(IDENTIFIER, USERNAME);
    assert_eq!(
        retrieved_credential.unwrap().password,
        NEW_PASSWORD,
        "Password should be updated to new password."
    );
    teardown(&tmpfile);
}
//
#[test]
fn updating_a_particular_credential_set_does_not_affect_others() {
    let tmpfile = generate_unique_file_path();
    let mut password_manager = PasswordManager::new(tmpfile.clone(), MASTERPASSWORD)
        .expect("could not create password manager");
    let _ = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);
    let _ = password_manager.store_password(IDENTIFIER, USERNAME2, PASSWORD2);
    let _ = password_manager.update_password(IDENTIFIER, USERNAME, NEW_PASSWORD);
    let retrieved_credentials = password_manager.retrieve_password(IDENTIFIER, USERNAME2);
    assert_eq!(
        retrieved_credentials.unwrap().password,
        PASSWORD2,
        "Password for second user should remain unchanged."
    );
    teardown(&tmpfile);
}

#[test]
fn deleting_a_particular_credential_set_does_not_affect_others() {
    let tmpfile = generate_unique_file_path();
    let mut password_manager = PasswordManager::new(tmpfile.clone(), MASTERPASSWORD)
        .expect("could not create password manager");
    let _ = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);
    let _ = password_manager.store_password(IDENTIFIER, USERNAME2, PASSWORD2);
    let _ = password_manager.update_password(IDENTIFIER, USERNAME, NEW_PASSWORD);
    let retrieved_password2 = password_manager.retrieve_password(IDENTIFIER, USERNAME2);
    assert_eq!(
        retrieved_password2.unwrap().password,
        PASSWORD2,
        "Password for second user should remain unchanged."
    );
    teardown(&tmpfile);
}

#[test]
fn it_reports_true_when_deleting_valid_credentials() {
    let tmpfile = generate_unique_file_path();
    let mut password_manager = PasswordManager::new(tmpfile.clone(), MASTERPASSWORD)
        .expect("could not create password manager");
    let _ = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);
    let delete_result = password_manager.delete_credential(IDENTIFIER, USERNAME);
    assert_eq!(
        delete_result,
        Ok(()),
        "Deleting an existing password should succeed."
    );
    teardown(&tmpfile);
}

#[test]
fn it_cannot_retrieve_a_deleted_password() {
    let tmpfile = generate_unique_file_path();
    let mut password_manager = PasswordManager::new(tmpfile.clone(), MASTERPASSWORD)
        .expect("could not create password manager");
    let _ = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);

    // Delete the password and assert that deletion was successful
    let delete_result = password_manager.delete_credential(IDENTIFIER, USERNAME);
    assert_eq!(
        delete_result,
        Ok(()),
        "Deleting an existing password should succeed."
    );

    // Attempt to retrieve the deleted password
    let retrieved_credential = password_manager.retrieve_password(IDENTIFIER, USERNAME);

    // Assert that the password cannot be retrieved after deletion
    assert!(
        retrieved_credential.is_none(),
        "A deleted password should not be retrievable."
    );
    teardown(&tmpfile);
}
//
// Tests that the method reports the correct status when attempting to delete a non-existent password.
#[test]
fn it_reports_failure_when_deleting_nonexistent_password() {
    let tmpfile = generate_unique_file_path();
    let mut password_manager = PasswordManager::new(tmpfile.clone(), MASTERPASSWORD)
        .expect("could not create password manager");
    let delete_result = password_manager.delete_credential(IDENTIFIER, USERNAME);
    assert!(
        delete_result.is_err(),
        "Deleting a non-existent password should fail."
    );
    teardown(&tmpfile);
}

// Tests that deleting one password does not affect other stored passwords.
#[test]
fn it_does_not_delete_other_passwords() {
    let tmpfile = generate_unique_file_path();
    let mut password_manager = PasswordManager::new(tmpfile.clone(), MASTERPASSWORD)
        .expect("could not create password manager");
    let _ = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);
    let _ = password_manager.store_password(IDENTIFIER, USERNAME2, PASSWORD2);
    let _ = password_manager.delete_credential(IDENTIFIER, USERNAME);
    assert!(
        !password_manager.has_password(IDENTIFIER, USERNAME),
        "The specified password should be deleted."
    );
    assert!(
        password_manager.has_password(IDENTIFIER, USERNAME2),
        "Other passwords should not be affected by the deletion of a different one."
    );
    teardown(&tmpfile);
}

#[test]
fn it_does_not_allow_identifiers_with_less_than_3_characters() {
    let tmpfile = generate_unique_file_path();
    let mut password_manager = PasswordManager::new(tmpfile.clone(), MASTERPASSWORD)
        .expect("could not create password manager");
    let store_result = password_manager.store_password("", USERNAME, PASSWORD);
    assert!(
        store_result.is_err(),
        "Passwords should not be allowed to be stored with an empty identifier."
    );
    teardown(&tmpfile);
}

#[test]
fn it_does_not_allow_identical_passwords() {
    let tmpfile = generate_unique_file_path();
    let mut password_manager = PasswordManager::new(tmpfile.clone(), MASTERPASSWORD)
        .expect("could not create password manager");

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
    teardown(&tmpfile);
}
