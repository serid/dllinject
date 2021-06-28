///! Extend iterator with an item at the end

use std::mem::swap;

pub struct ExtendIterator<I: Iterator> {
    iter: I,
    value: Option<I::Item>,
}

impl<I: Iterator> Iterator for ExtendIterator<I> {
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().or_else(|| {
            let mut local_value = None;
            swap(&mut self.value, &mut local_value);
            local_value
        })
    }
}

pub trait Extend: Iterator + Sized {
    fn extend(self, value: Self::Item) -> ExtendIterator<Self> {
        ExtendIterator {
            value: Some(value),
            iter: self,
        }
    }
}

impl<I: Iterator + Sized> Extend for I {}