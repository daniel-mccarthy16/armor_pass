use crate::generator::PasswordGenerator;
use crate::generator::PasswordGeneratorOptions;
use crate::password_manager::PasswordManager;
use crate::utility::print_credential;
use crate::utility::print_credential_list;
use std::io::{stdin, stdout, Write};
use std::path::PathBuf;

enum Command {
    Create(CreatePasswordOptions),
    Delete,
    Retrieve(RetrievePasswordOptions),
    Update,
    Quit,
}

#[derive(Default)]
struct CreatePasswordOptions {
    identifier: Option<String>,
    username: Option<String>,
    password_generator_options: PasswordGeneratorOptions,
}

#[derive(Default)]
struct RetrievePasswordOptions {
    identifier: Option<String>,
    username: Option<String>,
}

impl Command {
    fn from_str(command_str: &str) -> Option<Command> {
        match command_str {
            "create" => Some(Command::Create(CreatePasswordOptions::default())),
            "delete" => Some(Command::Delete),
            "retrieve" => Some(Command::Retrieve(RetrievePasswordOptions::default())),
            "update" => Some(Command::Update),
            "quit" => Some(Command::Quit),
            "exit" => Some(Command::Quit),
            _ => None,
        }
    }

    fn execute(&mut self, shell: &mut Shell) {
        match self {
            Command::Create(options) => shell.handle_create_command(options),
            Command::Delete => shell.handle_delete_command(),
            Command::Retrieve(options) => shell.handle_retrieve_command(options),
            Command::Update => shell.handle_update_command(),
            Command::Quit => shell.should_terminate = true,
        }
    }
}

enum ShellState {
    MainPrompt,
    AuthenticatePrompt,
}

pub struct Shell {
    command_history: Vec<String>,
    state: ShellState,
    authenticated: bool,
    should_terminate: bool,
    password_manager: Option<PasswordManager>,
}

impl Default for Shell {
    fn default() -> Shell {
        Shell {
            command_history: Vec::new(),
            authenticated: false,
            should_terminate: false,
            state: ShellState::AuthenticatePrompt,
            password_manager: None,
        }
    }
}

impl Shell {
    pub fn new() -> Shell {
        Shell::default()
    }

    fn prompt(&self, prompttext: &str) -> String {
        print!(">> {}", prompttext);
        stdout().flush().unwrap();

        let mut input = String::new();
        stdin().read_line(&mut input).expect("Failed to read line");

        input.trim().to_string()
    }

    pub fn run(&mut self) {
        while !self.should_terminate {
            match self.state {
                ShellState::MainPrompt => {
                    let input = self.prompt("Enter a command: ");
                    self.handle_main_command(&input);
                }
                ShellState::AuthenticatePrompt => {
                    let masterpassword = self.prompt("Please enter your master password sir: ");
                    self.handle_authentication_prompt(&masterpassword);
                }
            }
        }
    }

    fn handle_main_command(&mut self, input: &str) {
        if let Some(mut command) = Command::from_str(input) {
            command.execute(self);
        } else {
            self.show_root_prompt_help_message();
        }
    }

    fn show_root_prompt_help_message(&self) {
        println!("Welcome to the interactive shell! Here are the available commands:");
        println!("1. Create - Use this command to create a new item.");
        println!("2. Delete - Use this command to delete an existing item.");
        println!("3. Retrieve - Use this command to retrieve details of an existing item.");
        println!("4. Update - Use this command to update details of an existing item.");
        println!("5. Quit - Use this command to exit the application.");
        println!("\nType a command and press Enter to execute it.");
    }

    fn handle_authentication_prompt(&mut self, masterpassword: &str) {
        match PasswordManager::new(PathBuf::from("/tmp/armorpass.enc"), masterpassword) {
            Ok(password_manager) => {
                self.state = ShellState::MainPrompt;
                self.authenticated = true;
                self.password_manager = Some(password_manager);
            }
            Err(e) => {
                eprintln!("Failed auth attempt: {}", e);
            }
        }
    }

    fn handle_create_command(&mut self, options: &mut CreatePasswordOptions) {
        options.identifier = Some(self.prompt("Enter identifier (e.g., 'league of legends'): "));
        options.username =
            Some(self.prompt("Enter username, can have multiple usernames per identifier: "));

        options.password_generator_options.length =
            self.prompt_for_number("Enter desired length (default 20): ");

        options.password_generator_options.min_uppercase =
            self.prompt_for_number("Enter minimum number of uppercase characters (default 0): ");

        options.password_generator_options.min_special_characters =
            self.prompt_for_number("Enter minimum number of special characters (default 0: ");

        options.password_generator_options.min_numbers =
            self.prompt_for_number("Enter minimum number of numbers (default 0): ");

        options.password_generator_options.unicode =
            Some(self.prompt_for_confirmation("Do you want to use unicode? (default no): "));

        // After collecting all options.password_generator_options, create the PasswordGenerator
        let password_generator = PasswordGenerator::new(&options.password_generator_options);

        // Use password_generator to generate password or perform next steps
        let password = password_generator.generate();

        let identifier_ref = options
            .identifier
            .as_deref()
            .expect("[Error]: could not source an identifier for password creation");
        let username_ref = options
            .username
            .as_deref()
            .expect("[Error]: could not source an identifier for password creation");
        let password_manager = self.get_password_manager_mut();
        password_manager
            .store_password(identifier_ref, username_ref, &password)
            .expect("Failed to store password");
        self.state = ShellState::MainPrompt;
    }

    fn handle_delete_command(&self) {
        todo!()
    }
    fn handle_retrieve_command(&mut self, options: &mut RetrievePasswordOptions) {
        options.identifier = Some(self.prompt("Enter identifier (e.g., 'league of legends'): "));
        let username_input =
            self.prompt("Enter an optional username, can have multiple usernames per identifier: ");
        options.username = if username_input.trim().is_empty() {
            None
        } else {
            Some(username_input)
        };
        let identifier_ref = options
            .identifier
            .as_deref()
            .expect("[Error]: could not source an identifier for password creation");
        let password_manager = self.get_password_manager_mut();
        match options.username.as_ref().map(|s| s.as_str()) {
            Some(username_ref) => {
                match password_manager.retrieve_password(identifier_ref, username_ref) {
                    Some(credential) => {
                        print_credential(credential);
                    }
                    None => eprintln!(
                        "[Warn]: Could not find a record for that identifier/username combination"
                    ),
                }
            }
            None => {
                let credential_list = password_manager.retrieve_credentials(identifier_ref);
                if credential_list.is_empty() {
                    eprintln!("[Warn]: Could not find any records for that identifier");
                } else {
                    print_credential_list(credential_list);
                }
            }
        }
    }

    fn handle_update_command(&self) {
        todo!()
    }

    // Helper method to prompt for a number with a default value
    fn prompt_for_number(&self, prompt: &str) -> Option<usize> {
        let input = self.prompt(prompt);
        if input.trim().is_empty() {
            None
        } else {
            input.trim().parse().ok()
        }
    }

    fn prompt_for_confirmation(&self, prompt: &str) -> bool {
        let input = self.prompt(prompt).trim().to_lowercase();
        match input.as_str() {
            "y" | "yes" => true,
            _ => false,
        }
    }

    // Helper method to prompt with a default string value
    fn prompt_with_default(&self, prompt: &str, default: &str) -> String {
        let input = self.prompt(prompt);
        if input.is_empty() {
            default.to_string()
        } else {
            input
        }
    }

    fn get_password_manager_mut(&mut self) -> &mut PasswordManager {
        self.password_manager
            .as_mut()
            .expect("[Error]: havent yet unencrypted file for operation, authentication required")
    }
}
