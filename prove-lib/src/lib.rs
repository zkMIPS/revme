pub mod guest;
pub mod host;
mod utils;

#[cfg(test)]
mod tests {
    use crate::guest::verify_revm_tx;
    use crate::host::read_data;

    #[test]
    pub fn test_revme() {
        let manifest_path = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let json_path =
            std::env::var("JSON_PATH").unwrap_or(format!("{}/test-vectors/test.json", manifest_path));
        
        let data = read_data(&json_path).unwrap();
        assert!(verify_revm_tx(&data));
    }
}
