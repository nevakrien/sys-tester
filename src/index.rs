use std::fmt::{self, Debug};
use std::hash::Hash;
use std::marker::PhantomData;
use std::ops::{Index, IndexMut};

pub trait Idx: Copy + 'static + Eq + PartialEq + Debug + Hash {
    fn new(idx: usize) -> Self;
    fn index(self) -> usize;

    #[inline]
    fn increment_by(&mut self, amount: usize) {
        *self = self.plus(amount);
    }

    #[inline]
    #[must_use = "Use `increment_by` if you wanted to update the index in-place"]
    fn plus(self, amount: usize) -> Self {
        Self::new(self.index() + amount)
    }
}

impl Idx for usize {
    #[inline]
    fn new(idx: usize) -> Self {
        idx
    }

    #[inline]
    fn index(self) -> usize {
        self
    }
}

impl Idx for u32 {
    #[inline]
    fn new(idx: usize) -> Self {
        assert!(idx <= u32::MAX as usize);
        idx as u32
    }

    #[inline]
    fn index(self) -> usize {
        self as usize
    }
}

//INDEX SPAN
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct IndexSpan<I: Idx> {
    _start: I,
    _count: I,
}

impl<I: Idx> IndexSpan<I> {
    #[inline]
    pub fn new(start: I, count: usize) -> Self {
        Self {
            _start: start,
            _count: I::new(count),
        }
    }

    #[inline]
    pub fn start(&self) -> I {
        self._start
    }

    #[inline]
    pub fn len(&self) -> usize {
        self._count.index()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    pub fn at(&self, index: usize) -> I {
        debug_assert!(index < self.len(), "IndexSpan index out of bounds");
        self._start.plus(index)
    }

    #[inline]
    pub fn ids(&self) -> impl DoubleEndedIterator<Item = I> + ExactSizeIterator + '_ {
        (0..self.len()).map(|i| self._start.plus(i))
    }

    #[inline]
    pub fn subslice(&self, offset: usize, count: usize) -> Self {
        debug_assert!(offset <= self.len(), "IndexSpan offset out of bounds");
        debug_assert!(
            offset + count <= self.len(),
            "IndexSpan length out of bounds"
        );
        Self::new(self._start.plus(offset), count)
    }
}

// -----------------------------------------------------------------------------
// IndexSlice
// -----------------------------------------------------------------------------

#[derive(Copy, Clone)]
pub struct IndexSlice<'a, I: Idx, T> {
    raw: &'a [T],
    _marker: PhantomData<fn(I) -> I>,
}

impl<'a, I: Idx, T> IndexSlice<'a, I, T> {
    #[inline]
    pub fn new(raw: &'a [T]) -> Self {
        Self {
            raw,
            _marker: PhantomData,
        }
    }

    #[inline]
    pub fn raw(self) -> &'a [T] {
        self.raw
    }

    #[inline]
    pub fn len(self) -> usize {
        self.raw.len()
    }

    #[inline]
    pub fn is_empty(self) -> bool {
        self.raw.is_empty()
    }

    #[inline]
    pub fn get(self, index: I) -> Option<&'a T> {
        self.raw.get(index.index())
    }

    #[inline]
    pub fn iter(self) -> std::slice::Iter<'a, T> {
        self.raw.iter()
    }

    #[inline]
    pub fn iter_enumerated(self) -> impl ExactSizeIterator<Item = (I, &'a T)> {
        self.raw
            .iter()
            .enumerate()
            .map(|(i, value)| (I::new(i), value))
    }
}

impl<'a, I: Idx, T> Index<I> for IndexSlice<'a, I, T> {
    type Output = T;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        &self.raw[index.index()]
    }
}

impl<'a, I: Idx, T: Debug> Debug for IndexSlice<'a, I, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.raw.fmt(f)
    }
}

// -----------------------------------------------------------------------------
// IndexSliceMut
// -----------------------------------------------------------------------------

pub struct IndexSliceMut<'a, I: Idx, T> {
    raw: &'a mut [T],
    _marker: PhantomData<fn(I) -> I>,
}

impl<'a, I: Idx, T> IndexSliceMut<'a, I, T> {
    #[inline]
    pub fn new(raw: &'a mut [T]) -> Self {
        Self {
            raw,
            _marker: PhantomData,
        }
    }

    #[inline]
    pub fn raw(self) -> &'a mut [T] {
        self.raw
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.raw.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    #[inline]
    pub fn get(&self, index: I) -> Option<&T> {
        self.raw.get(index.index())
    }

    #[inline]
    pub fn get_mut(&mut self, index: I) -> Option<&mut T> {
        self.raw.get_mut(index.index())
    }

    #[inline]
    pub fn iter(&self) -> std::slice::Iter<'_, T> {
        self.raw.iter()
    }

    #[inline]
    pub fn iter_mut(&mut self) -> std::slice::IterMut<'_, T> {
        self.raw.iter_mut()
    }

    #[inline]
    pub fn iter_enumerated(&self) -> impl ExactSizeIterator<Item = (I, &T)> {
        self.raw
            .iter()
            .enumerate()
            .map(|(i, value)| (I::new(i), value))
    }

    #[inline]
    pub fn iter_enumerated_mut(&mut self) -> impl ExactSizeIterator<Item = (I, &mut T)> {
        self.raw
            .iter_mut()
            .enumerate()
            .map(|(i, value)| (I::new(i), value))
    }

    #[inline]
    pub fn pick2_mut(&mut self, a: I, b: I) -> (&mut T, &mut T) {
        let (ai, bi) = (a.index(), b.index());
        self.raw.get_disjoint_mut([ai, bi]).unwrap().into()
    }
}

impl<'a, I: Idx, T> Index<I> for IndexSliceMut<'a, I, T> {
    type Output = T;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        &self.raw[index.index()]
    }
}

impl<'a, I: Idx, T> IndexMut<I> for IndexSliceMut<'a, I, T> {
    #[inline]
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        &mut self.raw[index.index()]
    }
}

impl<'a, I: Idx, T: Debug> Debug for IndexSliceMut<'a, I, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.raw.fmt(f)
    }
}

// -----------------------------------------------------------------------------
// IndexVec
// -----------------------------------------------------------------------------

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct IndexVec<I: Idx, T> {
    raw: Vec<T>,
    _marker: PhantomData<fn(I) -> I>,
}

impl<I: Idx, T> IndexVec<I, T> {
    #[inline]
    pub fn new() -> Self {
        Self {
            raw: Vec::new(),
            _marker: PhantomData,
        }
    }

    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            raw: Vec::with_capacity(capacity),
            _marker: PhantomData,
        }
    }

    #[inline]
    pub fn from_raw(raw: Vec<T>) -> Self {
        Self {
            raw,
            _marker: PhantomData,
        }
    }

    #[inline]
    pub fn into_raw(self) -> Vec<T> {
        self.raw
    }

    #[inline]
    pub fn raw(&self) -> &[T] {
        &self.raw
    }

    #[inline]
    pub fn raw_mut(&mut self) -> &mut [T] {
        &mut self.raw
    }

    #[inline]
    pub fn as_slice(&self) -> IndexSlice<'_, I, T> {
        IndexSlice::new(&self.raw)
    }

    #[inline]
    pub fn as_mut_slice(&mut self) -> IndexSliceMut<'_, I, T> {
        IndexSliceMut::new(&mut self.raw)
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.raw.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.raw.capacity()
    }

    #[inline]
    pub fn clear(&mut self) {
        self.raw.clear();
    }

    #[inline]
    pub fn reserve(&mut self, additional: usize) {
        self.raw.reserve(additional);
    }

    #[inline]
    pub fn next_index(&self) -> I {
        I::new(self.raw.len())
    }

    #[inline]
    pub fn push(&mut self, value: T) -> I {
        let index = self.next_index();
        self.raw.push(value);
        index
    }

    #[inline]
    pub fn pop(&mut self) -> Option<T> {
        self.raw.pop()
    }

    #[inline]
    pub fn get(&self, index: I) -> Option<&T> {
        self.raw.get(index.index())
    }

    #[inline]
    pub fn get_mut(&mut self, index: I) -> Option<&mut T> {
        self.raw.get_mut(index.index())
    }

    #[inline]
    pub fn iter(&self) -> std::slice::Iter<'_, T> {
        self.raw.iter()
    }

    #[inline]
    pub fn iter_mut(&mut self) -> std::slice::IterMut<'_, T> {
        self.raw.iter_mut()
    }

    #[inline]
    pub fn iter_enumerated(&self) -> impl ExactSizeIterator<Item = (I, &T)> {
        self.raw
            .iter()
            .enumerate()
            .map(|(i, value)| (I::new(i), value))
    }

    #[inline]
    pub fn iter_enumerated_mut(&mut self) -> impl ExactSizeIterator<Item = (I, &mut T)> {
        self.raw
            .iter_mut()
            .enumerate()
            .map(|(i, value)| (I::new(i), value))
    }

    #[inline]
    pub fn pick2_mut(&mut self, a: I, b: I) -> (&mut T, &mut T) {
        let (ai, bi) = (a.index(), b.index());
        self.raw.get_disjoint_mut([ai, bi]).unwrap().into()
    }
}

impl<I: Idx, T> Default for IndexVec<I, T> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<I: Idx, T> Index<I> for IndexVec<I, T> {
    type Output = T;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        &self.raw[index.index()]
    }
}

impl<I: Idx, T> IndexMut<I> for IndexVec<I, T> {
    #[inline]
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        &mut self.raw[index.index()]
    }
}

impl<I: Idx, T: Debug> Debug for IndexVec<I, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.raw.fmt(f)
    }
}

impl<I: Idx, T> From<Vec<T>> for IndexVec<I, T> {
    #[inline]
    fn from(raw: Vec<T>) -> Self {
        Self::from_raw(raw)
    }
}

impl<I: Idx, T> FromIterator<T> for IndexVec<I, T> {
    #[inline]
    fn from_iter<It: IntoIterator<Item = T>>(iter: It) -> Self {
        Self::from_raw(iter.into_iter().collect())
    }
}

#[derive(Debug)]
pub struct UnionFind<I: Idx>(IndexVec<I, I>);
impl<I: Idx> UnionFind<I> {
    pub fn new() -> Self {
        Self(IndexVec::new())
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn push_singleton(&mut self) -> I {
        let id = self.0.next_index();
        self.0.push(id);
        id
    }

    pub fn clear(&mut self) {
        self.0.clear();
    }

    pub fn find_root(&mut self, idx: I) -> I {
        let p = self[idx];
        if p == idx {
            return idx;
        }
        let root = self.find_root(p);
        self[idx] = root;
        root
    }

    /// Returns a dense cluster ID for every element and the number of clusters.
    ///
    /// Cluster IDs are assigned in root-index order.
    pub fn cluster_map(&mut self) -> (IndexVec<I, I>, usize) {
        let mut map = IndexVec::from_raw(vec![I::new(0); self.len()]);
        let mut cluster_count = 0;

        for raw_index in 0..self.len() {
            let index = I::new(raw_index);
            self.find_root(index);
        }

        for raw_index in 0..self.len() {
            let index = I::new(raw_index);
            if self[index] == index {
                map[index] = I::new(cluster_count);
                cluster_count += 1;
            }
        }

        for raw_index in 0..self.len() {
            let index = I::new(raw_index);
            map[index] = map[self[index]];
        }

        (map, cluster_count)
    }

    pub fn from_raw(raw:IndexVec<I, I>)->Self{
        Self(raw)
    }

    pub fn to_raw(self)->IndexVec<I,I>{
        self.0
    }
}

impl<I: Idx> Default for UnionFind<I> {
    fn default() -> Self {
        Self::new()
    }
}

impl<I: Idx> Index<I> for UnionFind<I> {
    type Output = I;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        &self.0[index]
    }
}

impl<I: Idx> IndexMut<I> for UnionFind<I> {
    #[inline]
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        &mut self.0[index]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn union_find_cluster_map_is_dense() {
        let mut union_find = UnionFind::<u32>::from_raw(vec![1, 2, 2, 4, 4, 5].into());

        let (map, cluster_count) = union_find.cluster_map();

        assert_eq!(map.raw(), &[0_u32, 0, 0, 1, 1, 2]);
        assert_eq!(map[3_u32], 1);
        assert_eq!(cluster_count, 3);
    }

    #[test]
    fn union_find_cluster_map_handles_empty_input() {
        let mut union_find = UnionFind::<u32>::new();

        assert_eq!(
            union_find.cluster_map(),
            (IndexVec::<u32, u32>::new(), 0)
        );
    }
}
