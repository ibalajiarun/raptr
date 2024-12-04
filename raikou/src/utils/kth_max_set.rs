// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone)]
pub struct KthMaxMap<K, V> {
    max_k: BTreeMap<K, V>,
    rest: BTreeMap<K, V>,
    k: usize,
}

impl<K: Ord, V> KthMaxMap<K, V> {
    pub fn new(k: usize) -> Self {
        assert!(k >= 1);
        Self {
            max_k: BTreeMap::new(),
            rest: BTreeMap::new(),
            k,
        }
    }

    pub fn k_max(&self) -> &BTreeMap<K, V> {
        &self.max_k
    }

    pub fn kth_max_key(&self) -> Option<&K> {
        if self.max_k.len() == self.k {
            self.k_max().keys().next()
        } else {
            None
        }
    }

    pub fn len(&self) -> usize {
        self.max_k.len() + self.rest.len()
    }

    pub fn insert(&mut self, key: K, value: V) {
        match self.kth_max_key() {
            Some(kth_max_key) if key < *kth_max_key => {
                self.rest.insert(key, value);
            },
            _ => {
                self.max_k.insert(key, value);
                if self.max_k.len() > self.k {
                    let (k, v) = self.max_k.pop_last().unwrap();
                    self.rest.insert(k, v);
                }
            },
        }
    }
}
