use crate::password_manager::CredentialSet;
use prettytable::{row, Cell, Row, Table};

pub fn validate_username(username: &str) -> Result<(), &str> {
    if !is_at_least_three_characters_long(username) {
        Err("Username must be at least 3 characters long")
    } else {
        Ok(())
    }
}

pub fn validate_identifier(identifier: &str) -> Result<(), &str> {
    if !is_at_least_three_characters_long(identifier) {
        Err("Identifier must be at least 3 characters long")
    } else {
        Ok(())
    }
}

fn is_at_least_three_characters_long(password: &str) -> bool {
    password.len() >= 3
}

pub fn print_credential_list(credential_list: Vec<&CredentialSet>) {
    let mut table = Table::new();
    table.add_row(row!["Identifier", "Username", "Password"]);
    for credential in credential_list {
        table.add_row(Row::new(vec![
            Cell::new(&credential.identifier),
            Cell::new(&credential.username),
            Cell::new(&credential.password),
        ]));
    }
    table.printstd();
}

pub fn print_credential(credential: &CredentialSet) {
    let mut table = Table::new();
    table.add_row(row!["Identifier", "Username", "Password"]);
    table.add_row(Row::new(vec![
        Cell::new(&credential.identifier),
        Cell::new(&credential.username),
        Cell::new(&credential.password),
    ]));
    table.printstd();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_username() {
        assert_eq!(validate_username("user"), Ok(()));
        assert_eq!(
            validate_username("us"),
            Err("Username must be at least 3 characters long")
        );
    }

    #[test]
    fn test_validate_identifier() {
        assert_eq!(validate_identifier("id123"), Ok(()));
        assert_eq!(
            validate_identifier("id"),
            Err("Identifier must be at least 3 characters long")
        );
    }
}
