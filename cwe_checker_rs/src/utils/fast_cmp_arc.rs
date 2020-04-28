use crate::prelude::*;
use std::sync::Arc;
use std::ops::{Deref, DerefMut};
use crate::analysis::abstract_domain::AbstractDomain;

// TODO: This is a helper not only for abstract domains! It needs its own source file!
#[derive(Serialize, Deserialize, Debug, Hash, Clone)]
pub struct FastCmpArc<T>(pub Arc<T>);

impl<T: PartialEq + Eq> PartialEq for FastCmpArc<T> {
    fn eq(&self, other:&Self) -> bool {
        if Arc::ptr_eq(&self.0, &other.0) {
            true
        } else {
            self.0.eq(&other.0)
        }
    }
}

impl<T: Eq> Eq for FastCmpArc<T> {}

impl<T: AbstractDomain + Clone> AbstractDomain for FastCmpArc<T> {
    fn top(&self) -> Self {
        FastCmpArc(Arc::new(self.0.top()))
    }

    fn merge(&self, other: &Self) -> Self {
        if Arc::ptr_eq(&self.0, &other.0) {
            self.clone()
        } else {
            FastCmpArc(Arc::new(self.0.merge(&other.0)))
        }
    }
}

impl<T: PartialOrd + Ord> PartialOrd for FastCmpArc<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: PartialOrd + Ord> Ord for FastCmpArc<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if Arc::ptr_eq(&self.0, &other.0) {
            std::cmp::Ordering::Equal
        } else {
            self.0.cmp(&other.0)
        }
    }
}

impl<T> Deref for FastCmpArc<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: Clone> DerefMut for FastCmpArc<T> {
    fn deref_mut(&mut self) -> &mut T {
        Arc::make_mut(&mut self.0)
    }
}
