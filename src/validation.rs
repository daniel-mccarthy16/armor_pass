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

