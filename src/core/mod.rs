//! Core implementation of the RC5 paper. In this section we discuss
//! how the RC5 paper was implemented and what makes this implementation correct,
//! with regards to the paper. We also mention the differences where they exist.
//!
//! ## Naming
//! In comparison to the paper the implementation uses a more natural naming convention.
//!
//! | RC5 paper | Implementation     |
//! |-----------|--------------------|
//! | W         | [Word]             |
//! | w         | [WORD_BYTES] * 8   |
//! | r         | [ROUNDS]           |
//! | b         | [KEY_SIZE]         |
//! | K         | [Key]              |
//! | P         | [P]                |
//! | Q         | [Q]                |
//! | L         | [KeyAsWords]       |
//! | S         | [ExpandedKeyTable] |
//!
//! ## Primitive operations
//!
//! Operations as defined in the section 3 of the RC5 paper.
//!
//! 1. Two's complement addition and subtraction of words: [u32::wrapping_add], [u32::wrapping_sub].
//! 2. Bitwise exclusive or of words: [std::ops::BitXor::bitxor].
//! 3. Left/Right rotation of words: [u32::rotate_left], [u32::rotate_right].

pub mod consts;

use std::cmp::max;
use std::convert::TryInto;
use std::ops::{Add, Div, Mul, Sub};

use cipher::inout::InOut;
use cipher::Unsigned;
pub use consts::*;

use cipher::typenum::{Diff, Prod};
use cipher::typenum::{Quot, Sum};
use cipher::typenum::{U1, U2};
use generic_array::sequence::GenericSequence;
use generic_array::{typenum, ArrayLength, GenericArray};

pub fn encrypt_block<W, R>(mut block: InOut<'_, '_, Block<W>>, key: &ExpandedKeyTable<W, R>)
where
    W: Word,
    W::Bytes: Mul<U2>, // TODO: can move to word
    BlockSize<W>: ArrayLength<u8>,
    R: Unsigned,
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArrayLength<W>,
{
    let (mut a, mut b) = words_from_block::<W>(block.get_in());

    a = a.wrapping_add(key[0]);
    b = b.wrapping_add(key[1]);

    for i in 1..=R::USIZE {
        a = a.bitxor(b).rotate_left(b).wrapping_add(key[2 * i]);
        b = b.bitxor(a).rotate_left(a).wrapping_add(key[2 * i + 1]);
    }

    block_from_words::<W>(a, b, block.get_out())
}

pub fn decrypt_block<W, R>(mut block: InOut<'_, '_, Block<W>>, key: &ExpandedKeyTable<W, R>)
where
    W: Word,
    W::Bytes: typenum::Unsigned,
    W::Bytes: Mul<U2>,
    BlockSize<W>: ArrayLength<u8>,
    R: Unsigned,
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArrayLength<W>,
{
    let (mut a, mut b) = words_from_block::<W>(block.get_in());

    for i in (1..=R::USIZE).rev() {
        b = b.wrapping_sub(key[2 * i + 1]).rotate_right(a).bitxor(a);
        a = a.wrapping_sub(key[2 * i]).rotate_right(b).bitxor(b);
    }

    b = b.wrapping_sub(key[1]);
    a = a.wrapping_sub(key[0]);

    block_from_words::<W>(a, b, block.get_out())
}

fn words_from_block<W>(block: &Block<W>) -> (W, W)
where
    W: Word,
    W::Bytes: typenum::Unsigned,
    W::Bytes: Mul<U2>,
    BlockSize<W>: ArrayLength<u8>,
{
    // Block size is 2 * word::BYTES so the unwrap is safe
    let a = W::from_le_bytes(block[..W::Bytes::USIZE].try_into().unwrap());
    let b = W::from_le_bytes(block[W::Bytes::USIZE..].try_into().unwrap());

    (a, b)
}

fn block_from_words<W>(a: W, b: W, out_block: &mut Block<W>)
where
    W: Word,
    W::Bytes: typenum::Unsigned,
    W::Bytes: Mul<U2>,
    BlockSize<W>: ArrayLength<u8>,
{
    let (left, right) = out_block.split_at_mut(W::Bytes::USIZE);

    left.copy_from_slice(&a.to_le_bytes());
    right.copy_from_slice(&b.to_le_bytes());
}

// KeySize
// ROUNDS
pub fn substitute_key<W, R, B>(key: &Key<B>) -> ExpandedKeyTable<W, R>
where
    W: Word,
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArrayLength<W>,
    B: ArrayLength<u8>,
    B: Add<W::Bytes>,
    Sum<B, W::Bytes>: Sub<U1>,
    Diff<Sum<B, W::Bytes>, U1>: Div<W::Bytes>,
    Quot<Diff<Sum<B, W::Bytes>, U1>, W::Bytes>: ArrayLength<W>,
{
    let key_as_words = key_into_words::<W, B>(key);
    let expanded_key_table = initialize_expanded_key_table::<W, R>();

    mix_in::<W, R, B>(expanded_key_table, key_as_words)
}

fn key_into_words<W, B>(key: &Key<B>) -> KeyAsWords<W, B>
where
    W: Word,
    B: ArrayLength<u8>,
    W::Bytes: Unsigned,
    B: Add<W::Bytes>,
    Sum<B, W::Bytes>: Sub<U1>,
    Diff<Sum<B, W::Bytes>, U1>: Div<W::Bytes>,
    KeyAsWordsSize<W, B>: ArrayLength<W>,
{
    // can be uninitialized
    let mut key_as_words: GenericArray<W, KeyAsWordsSize<W, B>> = GenericArray::default();

    for i in (0..B::USIZE).rev() {
        key_as_words[i / W::Bytes::USIZE] =
            key_as_words[i / W::Bytes::USIZE].rotate_left(W::EIGHT) + key[i].into();
        // no need for wrapping addition since we are adding a byte sized uint onto an uint with its lsb byte zeroed
    }

    key_as_words
}

fn initialize_expanded_key_table<W, R>() -> ExpandedKeyTable<W, R>
where
    W: Word,
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArrayLength<W>,
{
    // must be zero initialized
    let mut expanded_key_table: GenericArray<W, Prod<Sum<R, U1>, U2>> =
        generic_array::GenericArray::generate(|_| W::ZERO); // TODO: use default

    expanded_key_table[0] = W::P;
    for i in 1..expanded_key_table.len() {
        expanded_key_table[i] = expanded_key_table[i - 1].wrapping_add(W::Q);
    }

    expanded_key_table
}

fn mix_in<W, R, B>(
    mut key_table: ExpandedKeyTable<W, R>,
    mut key_as_words: KeyAsWords<W, B>,
) -> ExpandedKeyTable<W, R>
where
    W: Word,
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArrayLength<W>,
    B: Add<W::Bytes>,
    Sum<B, W::Bytes>: Sub<U1>,
    Diff<Sum<B, W::Bytes>, U1>: Div<W::Bytes>,
    KeyAsWordsSize<W, B>: ArrayLength<W>,
{
    let (mut expanded_key_index, mut key_as_words_index) = (0, 0);
    let (mut a, mut b) = (W::ZERO, W::ZERO);

    for _ in 0..3 * max(key_as_words.len(), key_table.len()) {
        key_table[expanded_key_index] = key_table[expanded_key_index]
            .wrapping_add(a)
            .wrapping_add(b)
            .rotate_left(W::THREE);

        a = key_table[expanded_key_index];

        key_as_words[key_as_words_index] = key_as_words[key_as_words_index]
            .wrapping_add(a)
            .wrapping_add(b)
            // rhs <= word::BITS, which is an u8. so the unwrap is safe
            .rotate_left(a.wrapping_add(b));

        b = key_as_words[key_as_words_index];

        expanded_key_index = (expanded_key_index + 1) % key_table.len();
        key_as_words_index = (key_as_words_index + 1) % key_as_words.len();
    }

    key_table
}
