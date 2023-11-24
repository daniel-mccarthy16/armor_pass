use rand::{Rng, distributions::Uniform, seq::SliceRandom};

pub struct PasswordGenerator {
    length: usize,
    min_uppercase: usize,
    min_numbers: usize,
    min_special_characters: usize,
    unicode: bool,
}

impl Default for PasswordGenerator {
    fn default() -> PasswordGenerator {
        PasswordGenerator { length: 20, min_uppercase: 0, min_numbers: 0, min_special_characters: 0, unicode: false }
    }
}

impl PasswordGenerator {
    // Constructor to create a new PasswordGenerator with specified parameters
    pub fn new(length: usize, min_uppercase: usize, min_numbers: usize, min_special_characters: usize, unicode: bool) -> Self {
        PasswordGenerator {
            length,
            min_uppercase,
            min_numbers,
            min_special_characters,
            unicode,
        }
    }

    // Generates a password based on the specified criteria
    pub fn generate(&self) -> String {
        let mut password = String::new();
        if self.unicode == false {
            password = self.generate_ascii_password();
        } else {
            password = self.generate_unicode_password();
        }
        password
    }

    fn generate_ascii_password(&self) -> String {

        let mut password: Vec<char>  = Vec::new();
        let mut rng = rand::thread_rng();
        for _ in 0..self.min_numbers {
            password.push(self.generate_random_digit(&mut rng));
        }

        for _ in 0..self.min_special_characters {
            password.push(self.generate_random_special_char(&mut rng));
        }

        for _ in 0..self.min_numbers {
            password.push(self.generate_random_digit(&mut rng));
        }

        for _ in 0..self.min_uppercase {
            password.push(self.generate_random_uppercase(&mut rng));
        }

        while password.len() < self.length {
            password.push(self.generate_random_ascii_character(&mut rng));
        }

        password.shuffle(&mut rng);

        password.into_iter().collect()
    }

    fn generate_unicode_password(&self) -> String {
        let mut password = String::new();
        let mut rng = rand::thread_rng();
        for _ in 0..self.length {
            password.push(self.generate_random_unicode_character(&mut rng));
        }
        password
    }

    fn generate_random_ascii_character(&self, rng: &mut impl Rng) -> char {
        let printable_ascii_range = Uniform::new_inclusive(33u8, 126u8);
        rng.sample(printable_ascii_range) as char
    }

    fn generate_random_digit(&self, rng: &mut impl Rng) -> char {
        let digits_ascii_range  = Uniform::new_inclusive(48u8, 57u8);
        rng.sample(digits_ascii_range) as char
    }

    fn generate_random_uppercase(&self, rng: &mut impl Rng) -> char {
        let digits_ascii_range  = Uniform::new_inclusive(65u8, 90u8);
        rng.sample(digits_ascii_range) as char
    }

    fn generate_random_special_char(&self, rng: &mut impl Rng) -> char {
        let special_chars = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', '-', '=', '{', '}', '[', ']', '|', '\\', ':', ';', '\'', '"', '<', '>', ',', '.', '?', '/'];
        let index = rng.gen_range(0..special_chars.len());
        special_chars[index]
    }

    //TODO - need to build out these blacklists
    fn generate_random_unicode_character(&self, rng: &mut impl Rng) -> char {
        let blacklist_ranges = vec![
            (0x0000, 0x001F), // Example: Control characters in Basic Latin
            (0x0080, 0x009F), // Example: C1 control characters in Latin-1 Supplement
            (0x0080, 0x009F), // Example: C1 control characters in Latin-1 Supplement
        ];

        let blacklist_single_chars = vec![
            '\u{007F}', // Delete character
        ];

        loop {
            // Generate a random Unicode scalar value
            let char_candidate = std::char::from_u32(rng.gen_range(0x0000..=0x10FFFF)).unwrap();

            // Check if the character is in any of the blacklisted ranges
            let in_blacklist_range = blacklist_ranges.iter().any(|&(start, end)| {
                char_candidate as u32 >= start && char_candidate as u32 <= end
            });

            // Check if the character is a blacklisted single character
            let is_blacklisted_char = blacklist_single_chars.contains(&char_candidate);

            // If character is not blacklisted, return it
            if !in_blacklist_range && !is_blacklisted_char {
                return char_candidate;
            }
        }
    }
}

#[cfg(test)]

mod tests {
    use super::*;

    #[test]
    fn test_ascii_password_length() {
        let generator = PasswordGenerator {
            length: 15,
            ..Default::default()
        };
        let password = generator.generate();
        assert_eq!(password.len(), 15);
    }

    #[test]
    fn test_min_uppercase() {
        let generator = PasswordGenerator {
            min_uppercase: 3,
            ..Default::default()
        };
        let password = generator.generate();
        let min_uppercase = password.chars().filter(|c| c.is_uppercase()).count();
        assert!(min_uppercase >= 3, "Password does not contain enough uppercase characters");
    }

    #[test]
    fn test_min_numbers() {
        let generator = PasswordGenerator {
            min_numbers: 3,
            ..Default::default()
        };
        let password = generator.generate();
        let min_numbers = password.chars().filter(|c| c.is_numeric()).count();
        assert!(min_numbers >= 3, "Password does not contain enough digits");
    }

    #[test]
    fn test_unicode() {
        let generator = PasswordGenerator {
            unicode: true,
            length: 10,
            ..Default::default()
        };
        let password = generator.generate();
        let is_unicode = password.chars().any(|c| c as u32 > 127); //if all characters found were
        //ascii, it would be a christmas miracle
        assert_eq!(is_unicode, true);
    }
}

