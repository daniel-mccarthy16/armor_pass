#[derive(Default, serde::Serialize, serde::Deserialize)]
pub struct PasswordManager {
    records: Vec<CredentialSet>,
    file_path: String
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct CredentialSet {
    identifier: String,
    username: String,
    password: String,
}

impl PasswordManager {
    pub fn new() -> Self {
        PasswordManager {
            records: Vec::new(),
            file_path: "/tmp/armor_pass.enc".to_string(),
        }
    }

    pub fn store_password(&mut self, identifier: &str, username: &str, password: &str) -> Result<(), String> {

        Self::validate_password(password).map_err(|e| format!("Password is invalid: {}", e.to_string()))?;
        Self::validate_username(username).map_err(|e| format!("Username is invalid: {}", e.to_string()))?;
        Self::validate_identifier(identifier).map_err(|e| format!("Identifier is invalid: {}", e.to_string()))?;

        let new_credentials = CredentialSet {
            identifier: identifier.to_string(),
            username: username.to_string(),
            password: password.to_string(),
        };

        self.records.push(new_credentials);

        Self::persist_credentials(&self).map_err(|e| e.to_string())?;

        Ok(())
    }

    pub fn has_password(&self, identifier: &str, username: &str) -> bool {
       self.records.iter().any(|record| {
            record.identifier == identifier && record.username == username
        })
    }

    pub fn retrieve_password(&self, identifier: &str, username: &str) -> Option<&str> {
        self.records.iter()
            .find(|&record| record.identifier == identifier && record.username == username)
            .map(|record| record.password.as_str())
    }


    pub fn update_password(&mut self, identifier: &str, username: &str, new_password: &str) -> Result<(), String> {
        // Find a mutable reference to the record that needs updating.
        if let Some(record) = self.records.iter_mut()
            .find(|record| record.identifier == identifier && record.username == username)
        {
            // If found, update the password field.
            record.password = new_password.to_owned();
            Self::persist_credentials(&self).map_err(|e| e.to_string())?;
            Ok(())
        } else {
            // If not found, return an Err.
            Err(format!("No record found for identifier: {}, username: {}", identifier, username))
        }
    }

    pub fn delete_credential(&mut self, identifier: &str, username: &str) -> Result<(), String> {
        // Store the original length to determine if a record was deleted.
        let original_len = self.records.len();

        // Retain only the records that do not match the identifier and username.
        self.records.retain(|record| record.identifier != identifier || record.username != username);

        // Check if the records collection has changed in size.
        if self.records.len() == original_len {
            // No records were deleted, return an error.
            Err(format!("No record found for identifier: {}, username: {}", identifier, username))
        } else {
            // A record was deleted, persist the changes.
            Self::persist_credentials(self).map_err(|e| e.to_string())?;
            Ok(())
        }
    }


    pub fn retrieve_credentials(&self, identifier: &str) -> Vec<&CredentialSet> {
        self.records.iter()
            .filter(|&record| record.identifier == identifier)
            .collect()
    }

    // pub fn encrypt_password(&self, password: &str) -> String {
    //     "sdfsdfsdf"
    // }
    //
    // pub fn decrypt_password(&self, encrypted_password: &str) -> String {
    //     "sdfsdfsdf"
    // }
    //
    // pub fn save_to_disk(&self) -> std::io::Result<()> {
    // }
    //
    // pub fn load_from_disk() -> std::io::Result<Self> {
    // }
    //
    // pub fn is_password_valid(&self, password: &str) -> bool {
    // }
    //
    //
    fn persist_credentials(&self) -> Result<(), String> {
        let json_data = serde_json::to_string(&self.records)
            .map_err(|e| format!("Failed to serialize records to json: {}", e.to_string()))?;

        std::fs::write(&self.file_path, json_data.as_bytes())
            .map_err(|e| format!("Failed to write credentials to disk: {}", e.to_string()))?;

        Ok(())
    }

    fn contains_three_uppercase(password: &str) -> bool {
        password.chars().filter(|c| c.is_uppercase()).count() >= 3
    }

    fn contains_three_digits(password: &str) -> bool {
        password.chars().filter(|c| c.is_digit(10)).count() >= 3
    }

    fn is_at_least_fourteen_characters_long(password: &str) -> bool {
        password.len() >= 14
    }

    fn is_at_least_three_characters_long(password: &str) -> bool {
        password.len() >= 3
    }

    fn validate_password(password: &str) -> Result<(), &str> {
        if !Self::is_at_least_fourteen_characters_long(password) {
            return Err("Password must be at least 14 characters long")
        }
        if !Self::contains_three_uppercase(password) {
            return Err("Password must contain at least three uppercase letters")
        }
        if !Self::contains_three_digits(password) {
            return Err("Password must contain at least three digits")
        }
        Ok(())
    }


    fn validate_username(username: &str) -> Result<(), &str> {
        if !Self::is_at_least_three_characters_long(username) {
            return Err("Username must be at least 3 characters long");
        } else {
            return Ok(())
        }
    }

    fn validate_identifier(identifier: &str) -> Result<(), &str> {
        if !Self::is_at_least_three_characters_long(identifier) {
            return Err("Identifier must be at least 3 characters long");
        } else {
            return Ok(())
        }
    }
}
