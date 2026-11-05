use std::collections::HashMap;

/// Computes Shannon entropy of an input string in bits per byte.
/// Random / encrypted / base64-tunneled strings typically exhibit entropy > 4.2.
pub fn shannon_entropy(input: &str) -> f64 {
    if input.is_empty() {
        return 0.0;
    }

    let mut counts: HashMap<char, usize> = HashMap::new();
    for c in input.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }

    let len = input.len() as f64;
    let mut entropy = 0.0;

    for &count in counts.values() {
        let p = (count as f64) / len;
        entropy -= p * p.log2();
    }

    entropy
}
