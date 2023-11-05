#[cfg(test)]
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


#[test]
fn it_stores_a_password() {
    let password_manager = PasswordManager::new();
    assert_eq!(password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD), true);
    assert!(password_manager.has_password(IDENTIFIER, USERNAME));
}

#[test]
fn it_retrieves_multiple_passwords_for_same_identifier() {
    let password_manager = PasswordManager::new();
    password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);
    password_manager.store_password(IDENTIFIER, USERNAME2, PASSWORD2);

    let credentials = password_manager.retrieve_credentials(IDENTIFIER);
    assert_eq!(credentials.len(), 2);
}

#[test]
fn it_retrieves_the_correct_password() {
    let password_manager = PasswordManager::new();
    password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);
    password_manager.store_password(IDENTIFIER, USERNAME2, PASSWORD2);

    let retrieved_password = password_manager.retrieve_password(IDENTIFIER, USERNAME);
    assert_eq!(retrieved_password, Some(PASSWORD));
    
    let retrieved_password2 = password_manager.retrieve_password(IDENTIFIER, USERNAME2);
    assert_eq!(retrieved_password2, Some(PASSWORD2));
}


#[test]
fn it_reports_successful_password_updates() {
    let mut password_manager = PasswordManager::new();
    password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);
    
    let update_result = password_manager.update_password(IDENTIFIER, USERNAME, NEW_PASSWORD);
    assert!(update_result, "Password update should report success.");
}

#[test]
fn it_really_updates_the_password() {
    let mut password_manager = PasswordManager::new();
    password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);
    
    password_manager.update_password(IDENTIFIER, USERNAME, NEW_PASSWORD);
    let retrieved_password = password_manager.retrieve_password(IDENTIFIER, USERNAME);
    
    assert_eq!(retrieved_password, Some(NEW_PASSWORD), "Password should be updated to new password.");
}

#[test]
fn updating_a_particular_credential_set_does_not_affect_others() {
    let mut password_manager = PasswordManager::new();
    password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);
    password_manager.store_password(IDENTIFIER, USERNAME2, PASSWORD2);
    
    password_manager.update_password(IDENTIFIER, USERNAME, NEW_PASSWORD);
    let retrieved_password2 = password_manager.retrieve_password(IDENTIFIER, USERNAME2);
    
    assert_eq!(retrieved_password2, Some(PASSWORD2), "Password for second user should remain unchanged.");
}


#[test]
deleting_a_particular_credential_set_does_not_affect_others() {
    let mut password_manager = PasswordManager::new();
    password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);
    password_manager.store_password(IDENTIFIER, USERNAME2, PASSWORD2);
    
    password_manager.update_password(IDENTIFIER, USERNAME, NEW_PASSWORD);
    let retrieved_password2 = password_manager.retrieve_password(IDENTIFIER, USERNAME2);
    
    assert_eq!(retrieved_password2, Some(PASSWORD2), "Password for second user should remain unchanged.");
}


// fn delete_password(&mut self, identifier: &str, username: &str) -> bool;
// Tests that a password is successfully deleted.
#[test]
fn it_reports_true_when_deleting_valid_credentials() {
    let mut password_manager = PasswordManager::new();
    password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);

    let delete_result = password_manager.delete_password(IDENTIFIER, USERNAME);
    assert!(delete_result, "Deleting an existing password should succeed.");
}

#[test]
fn it_cannot_retrieve_a_deleted_password() {
    let mut password_manager = PasswordManager::new();
    password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);

    // Delete the password and assert that deletion was successful
    let delete_result = password_manager.delete_password(IDENTIFIER, USERNAME);
    assert!(delete_result, "Deleting an existing password should succeed.");

    // Attempt to retrieve the deleted password
    let retrieved_password = password_manager.retrieve_password(IDENTIFIER, USERNAME);

    // Assert that the password cannot be retrieved after deletion
    assert_eq!(retrieved_password, None, "A deleted password should not be retrievable.");
}

// Tests that the method reports the correct status when attempting to delete a non-existent password.
#[test]
fn it_reports_failure_when_deleting_nonexistent_password() {
    let mut password_manager = PasswordManager::new();

    let delete_result = password_manager.delete_password(IDENTIFIER, USERNAME);
    assert!(!delete_result, "Deleting a non-existent password should fail.");
}

// Tests that deleting one password does not affect other stored passwords.
#[test]
fn it_does_not_delete_other_passwords() {
    let mut password_manager = PasswordManager::new();
    password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);
    password_manager.store_password(IDENTIFIER, USERNAME2, PASSWORD2);

    password_manager.delete_password(IDENTIFIER, USERNAME);
    
    assert!(!password_manager.has_password(IDENTIFIER, USERNAME), "The specified password should be deleted.");
    assert!(password_manager.has_password(IDENTIFIER, USERNAME2), "Other passwords should not be affected by the deletion of a different one.");
}

#[test]
fn it_does_not_allow_empty_identifiers() {
    let mut password_manager = PasswordManger::new();
    let store_result = password_manager.store_password("", USERNAME, PASSWORD);
    
    assert!(
        !store_result,
        "Passwords should not be allowed to be stored with an empty identifier."
    );
}

#[test]
fn it_does_not_allow_empty_usernames() {
    let mut password_manager = PasswordManager::new();
    let store_result = password_manager.store_password(IDENTIFIER, "", PASSWORD);
    
    assert!(
        !store_result,
        "Passwords should not be allowed to be stored with an empty username."
    );
}

#[test]
fn it_does_not_allow_empty_passwords() {
    let mut password_manager = PasswordManager::new();
    let store_result = password_manager.store_password(IDENTIFIER, USERNAME, "");
    
    assert!(
        !store_result,
        "Passwords should not be allowed to be stored when empty."
    );
}


#[test]
fn it_does_not_allow_identical_passwords() {
    let mut password_manager = PasswordManager::new();
    
    // Store a password for the first time.
    let first_store_result = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);
    assert!(
        first_store_result,
        "The first attempt to store a password should succeed."
    );

    // Attempt to store the same password again.
    let second_store_result = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD);
    assert!(
        !second_store_result,
        "Storing an identical password for the same identifier and username should not be allowed."
    );
}

#[test]
fn it_does_not_allow_passwords_shorter_than_fourteen_characters() {
    let mut password_manager = PasswordManager::new();

    // Attempt to store a short password.
    let store_result = password_manager.store_password(IDENTIFIER, USERNAME, SHORT_PASSWORD);
    
    // Assert that storing a password with fewer than 10 characters fails.
    assert!(
        !store_result,
        "Passwords with fewer than 14 characters should not be allowed."
    );
}


#[test]
fn it_requires_at_least_three_uppercase_letters_in_password() {
    let mut password_manager = PasswordManager::new();
    let password_with_few_uppercase = "Pa1@word"; // Only two uppercase letters

    let store_result = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD_FEW_UPPERCASE);

    assert!(
        !store_result,
        "Passwords must contain at least three uppercase letters."
    );
}

#[test]
fn it_requires_at_least_three_digits_in_password() {
    let mut password_manager = PasswordManager::new();
    let password_with_few_digits = "Pass@Word"; // No digits

    let store_result = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD_FEW_DIGITS);

    assert!(
        !store_result,
        "Passwords must contain at least three digits."
    );
}

#[test]
fn it_requires_at_least_three_symbols_in_password() {
    let mut password_manager = PasswordManager::new();
    let password_with_few_symbols = "Pass1Word2"; // No symbols

    let store_result = password_manager.store_password(IDENTIFIER, USERNAME, PASSWORD_FEW_SYMBOLS);

    assert!(
        !store_result,
        "Passwords must contain at least three symbols."
    );
}


// it encrypts passwords

//store_password(&mut self, identifier: &str, username: &str, password: &str) -> bool: Stores a username/password combination under the provided identifier. Returns true if the operation was successful.
// has_password(&self, identifier: &str, username: &str) -> bool: Checks if a password exists for the given identifier and username.
// retrieve_credentials(&self, identifier: &str) -> Vec<(String, String)>: Retrieves all username/password pairs for a given identifier.
// retrieve_password(&self, identifier: &str, username: &str) -> Option<&str>: 
