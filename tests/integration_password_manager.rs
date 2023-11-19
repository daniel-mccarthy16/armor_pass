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
use armor_pass::encryption::CryptoManager;

fn teardown() {
    let _ = std::fs::remove_file("/tmp/armorpass.enc");
}

#[test]
fn it_stores_a_password() {
    let mut password_manager = PasswordManager::new("/tmp/armorpass.enc", MASTERPASSWORD).expect("could not create password manager");
    // println!("muh {:?}", password_manager);
    let result = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);
    println!("result is X: {:?}", result);
    assert_eq!(result.is_ok(), true);
    assert!(password_manager.has_password(IDENTIFIER, USERNAME));
    teardown();
}

#[test]
fn it_retrieves_multiple_passwords_for_same_identifier() {
    let mut password_manager = PasswordManager::new("/tmp/armorpass.enc", MASTERPASSWORD).expect("could not create password manager");
    let _ = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);
    let _ = password_manager.store_password(IDENTIFIER, USERNAME2, PASSWORD2);
    let credentials = password_manager.retrieve_credentials(IDENTIFIER);
    assert_eq!(credentials.len(), 2);
    teardown();
}

#[test]
fn it_retrieves_the_correct_password() {
    let mut password_manager = PasswordManager::new("/tmp/armorpass.enc", MASTERPASSWORD).expect("could not create password manager");
    let _ = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);
    let _ = password_manager.store_password(IDENTIFIER, USERNAME2, PASSWORD2);

    let retrieved_password = password_manager.retrieve_password(IDENTIFIER, USERNAME);
    assert_eq!(retrieved_password, Some(PASSWORD));
    
    let retrieved_password2 = password_manager.retrieve_password(IDENTIFIER, USERNAME2);
    assert_eq!(retrieved_password2, Some(PASSWORD2));
    teardown();
}

#[test]
fn it_reports_successful_password_updates() {
    let mut password_manager = PasswordManager::new("/tmp/armorpass.enc", MASTERPASSWORD).expect("could not create password manager");
    let _ = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);
    let update_result = password_manager.update_password(IDENTIFIER, USERNAME, NEW_PASSWORD);
    assert_eq!(update_result, Ok(()), "Password update should report success.");
    teardown();
}
//
#[test]
fn it_really_updates_the_password() {
    let mut password_manager = PasswordManager::new("/tmp/armorpass.enc", MASTERPASSWORD).expect("could not create password manager");
    let _ = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);
    let _ = password_manager.update_password(IDENTIFIER, USERNAME, NEW_PASSWORD);
    let retrieved_password = password_manager.retrieve_password(IDENTIFIER, USERNAME);
    assert_eq!(retrieved_password, Some(NEW_PASSWORD), "Password should be updated to new password.");
    teardown();
}
//
#[test]
fn updating_a_particular_credential_set_does_not_affect_others() {
    let mut password_manager = PasswordManager::new("/tmp/armorpass.enc", MASTERPASSWORD).expect("could not create password manager");
    let _ = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);
    let _ = password_manager.store_password(IDENTIFIER, USERNAME2, PASSWORD2);
    let _ = password_manager.update_password(IDENTIFIER, USERNAME, NEW_PASSWORD);
    let retrieved_password2 = password_manager.retrieve_password(IDENTIFIER, USERNAME2);
    assert_eq!(retrieved_password2, Some(PASSWORD2), "Password for second user should remain unchanged.");
    teardown();
}

#[test]
fn deleting_a_particular_credential_set_does_not_affect_others() {
    let mut password_manager = PasswordManager::new("/tmp/armorpass.enc", MASTERPASSWORD).expect("could not create password manager");
    let _ = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);
    let _ = password_manager.store_password(IDENTIFIER, USERNAME2, PASSWORD2);
    let _ = password_manager.update_password(IDENTIFIER, USERNAME, NEW_PASSWORD);
    let retrieved_password2 = password_manager.retrieve_password(IDENTIFIER, USERNAME2);
    assert_eq!(retrieved_password2, Some(PASSWORD2), "Password for second user should remain unchanged.");
    teardown();
}

#[test]
fn it_reports_true_when_deleting_valid_credentials() {
    let mut password_manager = PasswordManager::new("/tmp/armorpass.enc", MASTERPASSWORD).expect("could not create password manager");
    let _ = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);
    let delete_result = password_manager.delete_credential(IDENTIFIER, USERNAME);
    assert_eq!(delete_result, Ok(()), "Deleting an existing password should succeed.");
    teardown();
}

#[test]
fn it_cannot_retrieve_a_deleted_password() {
    let mut password_manager = PasswordManager::new("/tmp/armorpass.enc", MASTERPASSWORD).expect("could not create password manager");
    let _ = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);

    // Delete the password and assert that deletion was successful
    let delete_result = password_manager.delete_credential(IDENTIFIER, USERNAME);
    assert_eq!(delete_result, Ok(()), "Deleting an existing password should succeed.");

    // Attempt to retrieve the deleted password
    let retrieved_password = password_manager.retrieve_password(IDENTIFIER, USERNAME);

    // Assert that the password cannot be retrieved after deletion
    assert_eq!(retrieved_password, None, "A deleted password should not be retrievable.");
    teardown();
}
//
// Tests that the method reports the correct status when attempting to delete a non-existent password.
#[test]
fn it_reports_failure_when_deleting_nonexistent_password() {
    let mut password_manager = PasswordManager::new("/tmp/armorpass.enc", MASTERPASSWORD).expect("could not create password manager");
    let delete_result = password_manager.delete_credential(IDENTIFIER, USERNAME);
    assert!(delete_result.is_err(), "Deleting a non-existent password should fail.");
    teardown();
}

// Tests that deleting one password does not affect other stored passwords.
#[test]
fn it_does_not_delete_other_passwords() {
    let mut password_manager = PasswordManager::new("/tmp/armorpass.enc", MASTERPASSWORD).expect("could not create password manager");
    let _ = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);
    let _ = password_manager.store_password(IDENTIFIER, USERNAME2, PASSWORD2);
    let _ = password_manager.delete_credential(IDENTIFIER, USERNAME);
    assert!(!password_manager.has_password(IDENTIFIER, USERNAME), "The specified password should be deleted.");
    assert!(password_manager.has_password(IDENTIFIER, USERNAME2), "Other passwords should not be affected by the deletion of a different one.");
    teardown();
}

#[test]
fn it_does_not_allow_identifiers_with_less_than_3_characters() {
    let mut password_manager = PasswordManager::new("/tmp/armorpass.enc", MASTERPASSWORD).expect("could not create password manager");
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
    let mut password_manager = PasswordManager::new("/tmp/armorpass.enc", MASTERPASSWORD).expect("could not create password manager");
    let store_result = password_manager.store_password(IDENTIFIER, "", PASSWORD);
    
    assert!(
        store_result.is_err(),
        "Passwords should not be allowed to be stored with an empty username."
    );
    teardown();
}

#[test]
fn it_does_not_allow_empty_passwords() {
    let mut password_manager = PasswordManager::new("/tmp/armorpass.enc", MASTERPASSWORD).expect("could not create password manager");
    let store_result = password_manager.store_password(IDENTIFIER, USERNAME, "");
    assert!(
        store_result.is_err(),
        "Passwords should not be allowed to be stored when empty."
    );
    teardown();
}
#[test]
fn it_does_not_allow_identical_passwords() {
    let mut password_manager = PasswordManager::new("/tmp/armorpass.enc", MASTERPASSWORD).expect("could not create password manager");
    
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
    let mut password_manager = PasswordManager::new("/tmp/armorpass.enc", MASTERPASSWORD).expect("could not create password manager");
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
    let mut password_manager = PasswordManager::new("/tmp/armorpass.enc", MASTERPASSWORD).expect("could not create password manager");
    let store_result = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD_FEW_UPPERCASE);
    assert!(
        store_result.is_err(),
        "Passwords must contain at least three uppercase letters."
    );
    teardown();
}

#[test]
fn it_requires_at_least_three_digits_in_password() {
    let mut password_manager = PasswordManager::new("/tmp/armorpass.enc", MASTERPASSWORD).expect("could not create password manager");
    let store_result = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD_FEW_DIGITS);
    assert!(
        store_result.is_err(),
        "Passwords must contain at least three digits."
    );
    teardown();
}

#[test]
fn it_requires_at_least_three_symbols_in_password() {
    let mut password_manager = PasswordManager::new("/tmp/armorpass.enc", MASTERPASSWORD).expect("could not create password manager");
    let store_result = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD_FEW_SYMBOLS);
    assert!(
        store_result.is_err(),
        "Passwords must contain at least three symbols."
    );
    teardown();
}

#[test]
fn it_encrypts_and_decrypts_a_file() {
    let filepath = "test_encrypt_decrypt.txt";
    let data_to_encrypt = b"Hello, world!";
    let mut crypto_manager = CryptoManager::new(filepath, PASSWORD).unwrap();
    crypto_manager.encrypt_and_persist(data_to_encrypt).unwrap();
    let decrypted_data = crypto_manager.decrypt_and_retrieve().unwrap();
    assert_eq!(decrypted_data, data_to_encrypt, "Decrypted data should match the original data");
    teardown();
}

// fn it_retrieves_salt_from_encrypted_file
// fn it_retrieves_iv_from_encrypted_file

// fn it_does_not_store_credentials_as_utf8(){
//     let mut password_manager = PasswordManager::new("/tmp/armorpass.enc", MASTERPASSWORD).expect("could not create password manager");
//     let _ = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);
//     let file_contents = std::fs::read_to_string("/tmp/armor_pass.enc");
//     assert!(file_contents.is_ok(), "File was read as valid UTF-8 which indicates the file is not being encrypted after storing");
//     teardown();
// }
//
// #[test]
// fn it_does_not_store_passwords_as_plain_json() {
//     let mut password_manager = PasswordManager::new("/tmp/armorpass.enc", MASTERPASSWORD).expect("could not create password manager");
//     let _ = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);
//     let file_contents = std::fs::read("/tmp/armor_pass.enc").expect("Failed to read password file");
//     let parse_result: Result<serde_json::Value, _> = serde_json::from_slice(&file_contents);
//     assert!(parse_result.is_ok(), "File contents look like valid JSON, which may indicate they are not encrypted");
//     teardown();
// }

//MAKE SURE YOU CAN ENCRYPT ASSERT ENCRYPTION, THEN DEENCRYPT AND ASSERT PLAIN TEXT AND CREDENTIALS
//AGAIN

// it_stores_different_encrypted_passwords_for_identical_plain_passwords:
//
// Verify that when the same password is encrypted multiple times, it results in different encrypted outputs due to the use of a salt or initialization vector (IV).
// it_decrypts_password_to_original_form:
//
// Ensure that when a password is retrieved, it is decrypted back into its original plain text form.
// it_fails_to_decrypt_with_incorrect_key:
//
// Check that decryption fails or returns an incorrect result if the wrong encryption key is used.
// it_handles_encryption_and_decryption_of_special_characters_in_passwords:
//
// Verify that passwords with special characters are encrypted and decrypted correctly.
// it_preserves_encryption_after_updating_password:
//
// When a password is updated, ensure that the new password is encrypted before storage.
// it_does_not_expose_encryption_keys_or_salts:
//
// Make sure that encryption keys or salts are not stored with the encrypted passwords and are not easily accessible.
// it_verifies_encrypted_passwords_are_not_plain_text_when_persisted:
//
// When passwords are saved to disk or database, ensure they are indeed in encrypted form and not plain text.
// it_can_retrieve_and_decrypt_multiple_passwords_for_same_identifier:
//
// Test that multiple encrypted passwords can be retrieved and decrypted for the same identifier.
// it_does_not_decrypt_passwords_if_encryption_schemas_mismatch:
//
// If the system has multiple encryption methods (e.g., after an upgrade), ensure that a password encrypted with one schema is not decrypted with a different schema.
// it_ensures_encryption_algorithm_meets_security_standards:
//
// This might involve checking the length of the key, the algorithm used, or other properties that indicate the encryption is strong enough.
// it_allows_password_retrieval_only_with_correct_decryption_procedure:
//
// Validate that passwords can only be retrieved using the correct decryption procedure, which includes using the correct key and algorithm.
