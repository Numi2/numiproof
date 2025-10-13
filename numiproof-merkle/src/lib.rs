// File: numiproof-merkle/src/lib.rs
use numiproof_hash::{h2, DIGEST_LEN};

#[derive(Clone, Debug)]
pub struct MerkleTree {
    nodes: Vec<Vec<u8>>,
}
impl MerkleTree {
    pub fn build(leaves: &[Vec<u8>]) -> Self {
        let n = leaves.len().next_power_of_two();
        let mut nodes = vec![vec![0u8; DIGEST_LEN]; 2*n];
        for i in 0..n {
            nodes[n+i] = if i < leaves.len() { leaves[i].clone() } else { leaves[leaves.len()-1].clone() };
        }
        for i in (1..n).rev() {
            nodes[i] = h2("merkle.node", &nodes[i<<1], &nodes[i<<1|1]).to_vec();
        }
        Self { nodes }
    }
    pub fn root(&self) -> Vec<u8> { self.nodes[1].clone() }
    pub fn open(&self, mut idx: usize) -> Vec<Vec<u8>> {
        let mut path = Vec::new();
        let base = self.nodes.len()/2;
        idx += base;
        while idx > 1 {
            path.push(self.nodes[idx ^ 1].clone());
            idx >>= 1;
        }
        path
    }
    pub fn verify(root: &[u8], mut idx: usize, leaf: &[u8], path: &[Vec<u8>]) -> bool {
        let mut h = leaf.to_vec();
        for sib in path {
            h = if idx % 2 == 0 {
                h2("merkle.node", &h, sib).to_vec()
            } else {
                h2("merkle.node", sib, &h).to_vec()
            };
            idx >>= 1;
        }
        h == root
    }
}