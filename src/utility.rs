use crate::password_manager::CredentialSet;
use prettytable::{row, Cell, Row, Table};
use std::io::{stdin, stdout, Write};

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

pub fn prompt(prompttext: &str) -> String {
    print!(">> {}", prompttext);
    stdout().flush().unwrap();

    let mut input = String::new();
    stdin().read_line(&mut input).expect("Failed to read line");

    input.trim().to_string()
}

// Helper method to prompt for a number with a default value
pub fn prompt_for_number(prompttxt: &str) -> Option<usize> {
    let input = prompt(prompttxt);
    if input.trim().is_empty() {
        None
    } else {
        input.trim().parse().ok()
    }
}

pub fn prompt_for_confirmation(prompttxt: &str) -> bool {
    let input = prompt(prompttxt).trim().to_lowercase();
    match input.as_str() {
        "y" | "yes" => true,
        _ => false,
    }
}

// Helper method to prompt with a default string value
pub fn prompt_with_default(prompttxt: &str, default: &str) -> String {
    let input = prompt(prompttxt);
    if input.is_empty() {
        default.to_string()
    } else {
        input
    }
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
    fn test_validate_identifier() {
        assert_eq!(validate_identifier("id123"), Ok(()));
        assert_eq!(
            validate_identifier("id"),
            Err("Identifier must be at least 3 characters long")
        );
    }
}
