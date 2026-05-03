use std::env;
use std::fs;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        eprintln!("Ús: yara_rule_validator <rule_file>");
        std::process::exit(2);
    }

    let rule_path = &args[1];

    let source = match fs::read_to_string(rule_path) {
        Ok(content) => content,
        Err(error) => {
            eprintln!("Error llegint regla {}: {}", rule_path, error);
            std::process::exit(3);
        }
    };

    let mut compiler = yara_x::Compiler::new();

    compiler.define_global("filepath", "").unwrap();
    compiler.define_global("filename", "").unwrap();
    compiler.define_global("extension", "").unwrap();

    if let Err(error) = compiler.add_source(source.as_str()) {
        eprintln!("Error compilant {}: {}", rule_path, error);
        std::process::exit(4);
    }

    let _rules = compiler.build();

    println!("OK: {}", rule_path);
}