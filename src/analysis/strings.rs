use regex::bytes::Regex;

pub fn extract_strings(bytes: &[u8]) -> Vec<String> {
    let Ok(regex) = Regex::new(r"[\x20-\x7e]{4,}") else {
        return Vec::new();
    };

    regex
        .find_iter(bytes)
        .filter_map(|mat| String::from_utf8(mat.as_bytes().to_vec()).ok())
        .take(512)
        .collect()
}
