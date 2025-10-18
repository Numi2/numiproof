// File: numiproof-merkle/src/lib.rs
use numiproof_hash::{h2, DIGEST_LEN, DOM_MERKLE_NODE};
use rayon::prelude::*;

#[derive(Clone, Debug)]
pub struct MerkleTree {
    nodes: Vec<Vec<u8>>,
}
impl MerkleTree {
    pub fn build(leaves: &[Vec<u8>]) -> Self {
        let n = leaves.len().next_power_of_two();
        let mut nodes = vec![vec![0u8; DIGEST_LEN]; 2*n];
        // Fill leaves in parallel
        nodes[n..n+n].par_iter_mut().enumerate().for_each(|(i, slot)| {
            let val = if i < leaves.len() { &leaves[i] } else { &leaves[leaves.len()-1] };
            *slot = val.clone();
        });
        // Compute internal nodes; level-by-level parallelism
        for i in (1..n).rev() {
            // Small trees don't benefit; sequential is fine for upper levels
            nodes[i] = h2(DOM_MERKLE_NODE, &nodes[i<<1], &nodes[i<<1|1]).to_vec();
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
                h2(DOM_MERKLE_NODE, &h, sib).to_vec()
            } else {
                h2(DOM_MERKLE_NODE, sib, &h).to_vec()
            };
            idx >>= 1;
        }
        h == root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(i: u8) -> Vec<u8> { vec![i; DIGEST_LEN] }

    #[test]
    fn merkle_inclusion_first_middle_last() {
        // Build tree with non-power-of-two leaves to test padding
        let leaves = vec![leaf(1), leaf(2), leaf(3), leaf(4), leaf(5)];
        let mt = MerkleTree::build(&leaves);
        let root = mt.root();

        for (i, l) in leaves.iter().enumerate() {
            let path = mt.open(i);
            assert!(MerkleTree::verify(&root, i, l, &path));
        }
        // Check padded last index equals last real leaf in storage
        let n = leaves.len().next_power_of_two();
        let last_real = leaves.len() - 1;
        let path = mt.open(n - 1);
        assert!(MerkleTree::verify(&root, n - 1, &leaves[last_real], &path));
    }

    #[test]
    fn merkle_rejects_tampered_leaf_or_path() {
        let leaves = vec![leaf(9), leaf(8), leaf(7), leaf(6)];
        let mt = MerkleTree::build(&leaves);
        let root = mt.root();
        let idx = 2;
        let mut path = mt.open(idx);
        // Tamper with leaf
        let bad_leaf = leaf(0);
        assert!(!MerkleTree::verify(&root, idx, &bad_leaf, &path));
        // Tamper with path
        path[0][0] ^= 1;
        assert!(!MerkleTree::verify(&root, idx, &leaves[idx], &path));
    }
}