pub fn validate_password(password: &str) -> Result<(), &str> {
    if !is_at_least_fourteen_characters_long(password) {
        return Err("Password must be at least 14 characters long")
    }
    if !contains_three_uppercase(password) {
        return Err("Password must contain at least three uppercase letters")
    }
    if !contains_three_digits(password) {
        return Err("Password must contain at least three digits")
    }
    Ok(())
}


pub fn validate_username(username: &str) -> Result<(), &str> {
    if !is_at_least_three_characters_long(username) {
        return Err("Username must be at least 3 characters long");
    } else {
        return Ok(())
    }
}

pub fn validate_identifier(identifier: &str) -> Result<(), &str> {
    if !is_at_least_three_characters_long(identifier) {
        return Err("Identifier must be at least 3 characters long");
    } else {
        return Ok(())
    }
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
