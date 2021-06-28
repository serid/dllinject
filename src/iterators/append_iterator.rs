///! Append an item to iterator beginning

use std::mem::swap;

pub struct AppendIterator<I: Iterator> {
    iter: I,
    value: Option<I::Item>,
}

impl<I: Iterator> Iterator for AppendIterator<I> {
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        let mut local_value = None;
        swap(&mut self.value, &mut local_value);
        local_value.or_else(|| self.iter.next())
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = self.value.is_some() as usize; // 0 or 1 depending on whether item is present
        let iter_hint = self.iter.size_hint();
        (iter_hint.0 + n, iter_hint.1.map(|m| m + n))
    }
}

impl<I: Iterator + ExactSizeIterator> ExactSizeIterator for AppendIterator<I> {}

pub trait Append: Iterator + Sized {
    fn append(self, value: Self::Item) -> AppendIterator<Self> {
        AppendIterator {
            value: Some(value),
            iter: self,
        }
    }
}

impl<I: Iterator> Append for I {}