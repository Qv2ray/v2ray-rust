use std::collections::HashMap;
use std::slice::IterMut;
use std::vec::IntoIter;

pub(super) struct KeepInsertOrderMap<V> {
    data: Vec<(String, V)>,
    order: HashMap<String, usize>,
}

impl<V> KeepInsertOrderMap<V> {
    pub(super) fn new() -> Self {
        Self {
            data: vec![],
            order: Default::default(),
        }
    }
    pub(super) fn insert(&mut self, key: String, v: V) {
        if self.order.get(key.as_str()).is_none() {
            self.order.insert(key.clone(), self.data.len());
            self.data.push((key, v));
        }
    }

    pub(super) fn get_mut<K: AsRef<str>>(&mut self, k: K) -> Option<&mut V> {
        if let Some(idx) = self.order.get(k.as_ref()) {
            Some(&mut self.data[*idx].1)
        } else {
            None
        }
    }

    pub(super) fn contains_key<K: AsRef<str>>(&self, k: K) -> bool {
        self.order.contains_key(k.as_ref())
    }

    pub(super) fn into_iter(self) -> IntoIter<(String, V)> {
        self.data.into_iter()
    }

    pub(super) fn iter_mut(&mut self) -> IterMut<'_, (String, V)> {
        self.data.iter_mut()
    }
}

impl<V> From<KeepInsertOrderMap<V>> for Vec<(String, V)> {
    fn from(m: KeepInsertOrderMap<V>) -> Self {
        m.data
    }
}
