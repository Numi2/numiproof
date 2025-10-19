use serde::{Serialize, Deserialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Params {
    /// Log2 blowup for low-degree extension (N -> N<<r)
    pub blowup_log2: Option<u32>,
    /// Number of FRI folding rounds
    pub fri_rounds: Option<u32>,
    /// Number of query positions for openings
    pub queries: Option<usize>,
}

impl Default for Params {
    fn default() -> Self { Self { blowup_log2: Some(2), fri_rounds: Some(1), queries: Some(32) } }
}

/// Parse prover/verifier parameters from TOML text
pub fn load_params_toml(input: &str) -> Result<Params, toml::de::Error> {
    toml::from_str::<Params>(input)
}

