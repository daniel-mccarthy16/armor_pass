use std::collections::HashMap;

pub struct Node {
    children: HashMap<char, Node>, 
    terminal: bool
}
impl Node {
 
    fn new () -> Self {
        Node {
            terminal: false,
            children: HashMap::new()
        }
    }
}

pub struct Autocomplete {
    root_node_pointer : Node,
}

impl Autocomplete {


    pub fn new(wordlist: &[&str]) -> Self {
        let mut autocomplete = Autocomplete {
            root_node_pointer: Node::new(),
        };

        for word in wordlist.iter() {
            autocomplete.add_to_trie(&word);
        }

        autocomplete
    }

    fn add_to_trie ( &mut self, word: &str ) {
        let mut current_node: &mut Node = &mut self.root_node_pointer;
        for char in word.chars() {
            //if an entry already exists in hash for char return it, else insert a new node and
            //return that instead
            current_node = current_node.children.entry(char).or_insert_with(Node::new)
        }
        current_node.terminal = true;
    }

    pub fn autocomplete ( &self, word: &str ) -> Vec<String> {

        let mut suggestions = Vec::new();
        let mut nodepointer: &Node = &self.root_node_pointer;

        //walk tree as low as we can, if we cant make it to the bottom for the word provided then
        //no suggestsions exist so bail out
        for char in word.chars() {
            match nodepointer.children.get(&char) {
                Some(node) => {
                    nodepointer = node;
                }
                None => return suggestions,
            }
        }

        self.find_word_suggestions( word , &nodepointer, &mut suggestions);

        suggestions
    }

    fn find_word_suggestions ( &self, word: &str, node: &Node, suggestions: &mut Vec<String> ) -> () {

        //break out condition
        if node.terminal == true {
            suggestions.push(word.to_string());
        }

        for (letter, childnode) in &node.children {
            let newword = format!("{}{}", word,  letter);
            self.find_word_suggestions ( &newword, childnode, suggestions ) ;
        }

    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_autocomplete() {
        let mut autocomplete = Autocomplete::new(&[]);
        autocomplete.add_to_trie("app");
        autocomplete.add_to_trie("apple");
        autocomplete.add_to_trie("yolo");
        let suggestions = autocomplete.autocomplete("ap");
        assert_eq!(suggestions, vec!["app", "apple"]);
    }

    #[test]
    fn test_add_and_autocomplete_using_constructor() {
        let autocomplete = Autocomplete::new(&["apple", "app", "yolo"]);
        let suggestions = autocomplete.autocomplete("ap");
        assert_eq!(suggestions, vec!["app", "apple"]);
    }

    #[test]
    fn test_add_and_autocomplete_using_repeated_words() {
        let autocomplete = Autocomplete::new(&["apple", "apple", "apple"]);
        let suggestions = autocomplete.autocomplete("ap");
        assert_eq!(suggestions, vec!["apple"]);
    }

}
