mod parser;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let file_path = "datasets/benign/package.json";
    parser::parse_content(file_path);

    Ok(())
}
