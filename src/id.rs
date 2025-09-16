use rand::{Rng, rngs::ThreadRng};

// Uppercase, lowercase, digits
const ALPHABET: &[char] = &[
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9',
];

pub struct ShortCodeGenerator {
    rng: ThreadRng,
    length: usize,
    alphabet: Vec<char>,
}

impl ShortCodeGenerator {
    pub fn new(length: usize) -> Self {
        Self {
            length,
            rng: rand::thread_rng(),
            alphabet: ALPHABET.to_vec(),
        }
    }

    pub fn next(&mut self) -> String {
        (0..self.length)
            .map(|_| {
                let idx = self.rng.gen_range(0, self.alphabet.len());
                self.alphabet[idx]
            })
            .collect()
    }
}
