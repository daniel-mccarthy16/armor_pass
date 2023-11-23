use rand::{Rng, distributions::Uniform};

pub struct PasswordGenerator {
    length: usize,
    uppercase_count: usize,
    numbers_count: usize,
    unicode: bool,
}

impl Default for PasswordGenerator {
    fn default() -> PasswordGenerator {
        PasswordGenerator { length: 20, uppercase_count: 5, numbers_count: 5, unicode: false }
    }
}

impl PasswordGenerator {
    // Constructor to create a new PasswordGenerator with specified parameters
    pub fn new(length: usize, uppercase_count: usize, numbers_count: usize, unicode: bool) -> Self {
        PasswordGenerator {
            length,
            uppercase_count,
            numbers_count,
            unicode,
        }
    }

    // Generates a password based on the specified criteria
    pub fn generate(&self) -> String {
        let mut password = String::new();
        if (self.unicode == false) {
            password = self.generate_ascii_password();
        } else {
            password = "TODO:implementunicode".to_string();
        }
        password
    }

    fn generate_ascii_password(&self) -> String {
        let mut password = String::new();
        let mut rng = rand::thread_rng();
        for _ in 0..self.length {
            password.push(self.generate_random_ascii_character(&mut rng));
        }
        password
    }

    fn generate_random_character(&self, rng: &mut impl Rng) -> char {
        let printable_ascii_range = Uniform::new_inclusive(33u8, 126u8);
        rng.sample(printable_ascii_range) as char
    }

    fn generate_random_digit(&self, rng: &mut impl Rng) -> char {
        let digits_ascii_range  = Uniform::new_inclusive(48u8, 57u8);
        rng.sample(digits_ascii_range) as char
    }

    fn generate_random_special_char(&self, rng: &mut impl Rng) -> char {
        let special_chars = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', '-', '=', '{', '}', '[', ']', '|', '\\', ':', ';', '\'', '"', '<', '>', ',', '.', '?', '/'];
        let index = rng.gen_range(0..special_chars.len());
        special_chars[index]
    }
}

#[cfg(test)]

mod tests {
    use super::*;

    #[test]
    fn test_ascii_password_length() {
        let generator = PasswordGenerator {
            length: 10,
            uppercase_count: 0,
            numbers_count: 0,
            unicode: false,
        };
        let password = generator.generate();
        assert_eq!(password.len(), 10);
    }

    #[test]
    fn test_uppercase_count() {
        let generator = PasswordGenerator {
            length: 10,
            uppercase_count: 3,
            numbers_count: 0,
            unicode: false,
        };
        let password = generator.generate();
        let uppercase_count = password.chars().filter(|c| c.is_uppercase()).count();
        assert_eq!(uppercase_count, 3);
    }

    #[test]
    fn test_numbers_count() {
        let generator = PasswordGenerator {
            length: 10,
            uppercase_count: 0,
            numbers_count: 3,
            unicode: false,
        };
        let password = generator.generate();
        let numbers_count = password.chars().filter(|c| c.is_numeric()).count();
        assert_eq!(numbers_count, 3);
    }

    #[test]
    fn test_unicode() {
        let generator = PasswordGenerator {
            length: 10,
            uppercase_count: 0,
            numbers_count: 0,
            unicode: true,
        };
        let password = generator.generate();
        // Assuming the unicode flag means the password might contain non-ASCII characters
        // This is a basic check and might need to be more sophisticated depending on the implementation
        let is_unicode = password.chars().any(|c| c as u32 > 127);
        assert_eq!(is_unicode, true);
    }
}



// Additional helper functions or types can be added outside the impl block if needed.
