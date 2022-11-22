//! Constants and types used in the implementation of the RC5-32/12/16 cipher. For further reference check the [RC5 paper] and the
//! [Naming][crate::core#naming] section in the module documentation.
//!
//! [RC5 paper]: https://www.grc.com/r&d/rc5.pdf

use std::ops::{Add, BitXor};

use cipher::typenum::{Diff, Prod, Quot, Sum, U1, U2, U4};
use generic_array::{ArrayLength, GenericArray};

// TODO: Sealed
pub trait Word: Default + Copy + From<u8> + Add<Output = Self> {
    type Bytes: ArrayLength<u8>;

    const ZERO: Self;
    const THREE: Self;
    const EIGHT: Self;

    const P: Self;
    const Q: Self;

    fn wrapping_add(self, rhs: Self) -> Self;
    fn wrapping_sub(self, rhs: Self) -> Self;

    fn rotate_left(self, n: Self) -> Self;
    fn rotate_right(self, n: Self) -> Self;

    fn from_le_bytes(bytes: &GenericArray<u8, Self::Bytes>) -> Self;
    fn to_le_bytes(self) -> GenericArray<u8, Self::Bytes>;

    fn bitxor(self, other: Self) -> Self;
}

impl Word for u32 {
    type Bytes = U4;

    const ZERO: Self = 0;
    const THREE: Self = 3;
    const EIGHT: Self = 8;

    const P: Self = 0xb7e15163;
    const Q: Self = 0x9e3779b9;

    fn wrapping_add(self, rhs: Self) -> Self {
        u32::wrapping_add(self, rhs)
    }

    fn wrapping_sub(self, rhs: Self) -> Self {
        u32::wrapping_sub(self, rhs)
    }

    fn rotate_left(self, n: Self) -> Self {
        u32::rotate_left(self, n)
    }

    fn rotate_right(self, n: Self) -> Self {
        u32::rotate_right(self, n)
    }

    fn from_le_bytes(bytes: &GenericArray<u8, Self::Bytes>) -> Self {
        u32::from_le_bytes(bytes.to_owned().into())
    }

    fn to_le_bytes(self) -> GenericArray<u8, Self::Bytes> {
        u32::to_le_bytes(self).into()
    }

    fn bitxor(self, other: Self) -> Self {
        <u32 as BitXor>::bitxor(self, other)
    }
}

pub type BlockSize<W> = Prod<<W as Word>::Bytes, U2>;
pub type ExpandedKeyTableSize<R> = Prod<Sum<R, U1>, U2>;
pub type KeyAsWordsSize<W, B> = Quot<Diff<Sum<B, <W as Word>::Bytes>, U1>, <W as Word>::Bytes>;

pub type Block<W> = generic_array::GenericArray<u8, BlockSize<W>>;
pub type Key<B> = generic_array::GenericArray<u8, B>;
pub type ExpandedKeyTable<W, R> = generic_array::GenericArray<W, ExpandedKeyTableSize<R>>;
pub type KeyAsWords<W, B> = generic_array::GenericArray<W, KeyAsWordsSize<W, B>>;
