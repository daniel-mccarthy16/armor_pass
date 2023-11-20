pub fn validate_password(password: &str) -> Result<(), &str> {
    if !is_at_least_fourteen_characters_long(password) {
        Err("Password must be at least 14 characters long")
    } else if !contains_three_uppercase(password) {
        Err("Password must contain at least three uppercase letters")
    } else if !contains_three_digits(password) {
        Err("Password must contain at least three digits")
    } else {
        Ok(())
    }
}

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

fn contains_three_uppercase(password: &str) -> bool {
    password.chars().filter(|c| c.is_uppercase()).count() >= 3
}

fn contains_three_digits(password: &str) -> bool {
    password.chars().filter(|c| c.is_ascii_digit()).count() >= 3
}

fn is_at_least_fourteen_characters_long(password: &str) -> bool {
    password.len() >= 14
}

fn is_at_least_three_characters_long(password: &str) -> bool {
    password.len() >= 3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_password() {
        assert_eq!(validate_password("ikwefwefwdfss567!%^LOL"), Ok(()));
        assert_eq!(validate_password("fs567!%^LOL"), Err("Password must be at least 14 characters long"));
        assert_eq!(validate_password("ikwefwefwdfss!%^LOL"), Err("Password must contain at least three digits"));
        assert_eq!(validate_password("ikwefwefwdfss567!%^"), Err("Password must contain at least three uppercase letters"));
    }

    #[test]
    fn test_validate_username() {
        assert_eq!(validate_username("user"), Ok(()));
        assert_eq!(validate_username("us"), Err("Username must be at least 3 characters long"));
    }

    #[test]
    fn test_validate_identifier() {
        assert_eq!(validate_identifier("id123"), Ok(()));
        assert_eq!(validate_identifier("id"), Err("Identifier must be at least 3 characters long"));
    }
}
