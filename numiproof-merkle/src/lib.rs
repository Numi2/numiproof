// File: numiproof-merkle/src/lib.rs
use numiproof_hash::{h2, DIGEST_LEN};
use serde::{Serialize, Deserialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleTree {
    nodes: Vec<[u8; DIGEST_LEN]>,
    leaf_count: usize,
}
impl MerkleTree {
    pub fn build(leaves: &[[u8; DIGEST_LEN]]) -> Self {
        let mut n = leaves.len().next_power_of_two();
        let mut nodes = vec![[0u8; DIGEST_LEN]; 2*n];
        for i in 0..n {
            nodes[n+i] = if i < leaves.len() { leaves[i] } else { leaves[leaves.len()-1] };
        }
        for i in (1..n).rev() {
            nodes[i] = h2("merkle.node", &nodes[i<<1], &nodes[i<<1|1]);
        }
        Self { nodes, leaf_count: leaves.len() }
    }
    pub fn root(&self) -> [u8; DIGEST_LEN] { self.nodes[1] }
    pub fn open(&self, mut idx: usize) -> Vec<[u8; DIGEST_LEN]> {
        let mut path = Vec::new();
        let base = self.nodes.len()/2;
        idx += base;
        while idx > 1 {
            path.push(self.nodes[idx ^ 1]);
            idx >>= 1;
        }
        path
    }
    pub fn verify(root: [u8; DIGEST_LEN], mut idx: usize, leaf: [u8; DIGEST_LEN], path: &[[u8; DIGEST_LEN]]) -> bool {
        let mut h = leaf;
        for sib in path {
            h = if idx % 2 == 0 { h2("merkle.node", &h, sib) } else { h2("merkle.node", sib, &h) };
            idx >>= 1;
        }
        h == root
    }
}