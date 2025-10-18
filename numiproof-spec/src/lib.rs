use serde::{Serialize, Deserialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Params {
    pub blowup_log2: Option<u32>,
    pub fri_rounds: Option<u32>,
    pub queries: Option<usize>,
}

impl Default for Params {
    fn default() -> Self { Self { blowup_log2: Some(2), fri_rounds: Some(1), queries: Some(32) } }
}

pub fn load_params_toml(input: &str) -> Result<Params, toml::de::Error> {
    toml::from_str::<Params>(input)
}

