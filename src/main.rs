mod encryption;
mod generator;
mod validation;
pub mod shell;
pub mod password_manager;

use crate::shell::Shell;


fn main() {
   let mut armor_pass_shell = Shell::new(); 
   armor_pass_shell.run(); 
}
