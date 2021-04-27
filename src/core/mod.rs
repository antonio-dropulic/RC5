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
use std::{convert::TryInto, ops::BitXor};

pub use consts::*;

pub fn encrypt_block(block: &Block, key: &ExpandedKeyTable) -> Block {
    let (mut a, mut b) = words_from_block(block);

    a = a.wrapping_add(key[0]);
    b = b.wrapping_add(key[1]);

    for i in 1..=ROUNDS as usize {
        a = a
            .bitxor(b)
            // rhs <= word::BITS, which is an u8. so the unwrap is safe
            .rotate_left((b % word::BITS as Word).try_into().unwrap())
            .wrapping_add(key[2 * i]);
        b = b
            .bitxor(a)
            // rhs <= word::BITS, which is an u8. so the unwrap is safe
            .rotate_left((a % word::BITS as Word).try_into().unwrap())
            .wrapping_add(key[2 * i + 1]);
    }

    block_from_words(a, b)
}

pub fn decrypt_block(block: &Block, key: &ExpandedKeyTable) -> Block {
    let (mut a, mut b) = words_from_block(block);

    for i in (1..=ROUNDS as usize).rev() {
        b = b
            .wrapping_sub(key[2 * i + 1])
            .rotate_right((a % word::BITS as Word).try_into().unwrap())
            .bitxor(a);
        a = a
            .wrapping_sub(key[2 * i])
            .rotate_right((b % word::BITS as Word).try_into().unwrap())
            .bitxor(b);
    }

    b = b.wrapping_sub(key[1]);
    a = a.wrapping_sub(key[0]);

    block_from_words(a, b)
}

pub fn substitute_key(key: &Key) -> ExpandedKeyTable {
    let key_as_words = key_into_words(key);
    let expanded_key_table = initialize_expanded_key_table();

    mix_in(expanded_key_table, key_as_words)
}

fn words_from_block(block: &Block) -> (Word, Word) {
    // Block size is 2 * word::BYTES so the unwrap is safe
    let a = Word::from_le_bytes(block[..word::BYTES].try_into().unwrap());
    let b = Word::from_le_bytes(block[word::BYTES..].try_into().unwrap());

    (a, b)
}

fn block_from_words(a: Word, b: Word) -> Block {
    // can be uninitialized
    let mut block = [0_u8; block::BYTES];
    let (left, right) = block.split_at_mut(word::BYTES);

    left.copy_from_slice(&a.to_le_bytes());
    right.copy_from_slice(&b.to_le_bytes());

    block
}

fn key_into_words(key: &Key) -> KeyAsWords {
    // can be uninitialized
    let mut key_as_words = [Word::MIN; key_as_words::SIZE];

    for i in (0..key::BYTES as usize).rev() {
        key_as_words[i / word::BYTES] =
            key_as_words[i / word::BYTES].rotate_left(u8::BITS) + key[i] as Word;
        // no need for wrapping addition since we are adding a byte sized uint onto an uint with its lsb byte zeroed
    }

    key_as_words
}

fn initialize_expanded_key_table() -> ExpandedKeyTable {
    // must be zero initialized
    let mut expanded_key_table = [Word::MIN; expanded_key_table::SIZE];

    expanded_key_table[0] = word::p();
    for i in 1..expanded_key_table::SIZE {
        expanded_key_table[i] = expanded_key_table[i - 1].wrapping_add(word::q());
    }

    expanded_key_table
}

fn mix_in(mut key_table: ExpandedKeyTable, mut key_as_words: KeyAsWords) -> ExpandedKeyTable {
    let (mut expanded_key_index, mut key_as_words_index) = (0, 0);
    let (mut a, mut b) = (0, 0);

    for _ in 0..3 * max(key_as_words::SIZE, expanded_key_table::SIZE) {
        key_table[expanded_key_index] = key_table[expanded_key_index]
            .wrapping_add(a)
            .wrapping_add(b)
            .rotate_left(3);

        a = key_table[expanded_key_index];

        key_as_words[key_as_words_index] = key_as_words[key_as_words_index]
            .wrapping_add(a)
            .wrapping_add(b)
            // rhs <= word::BITS, which is an u8. so the unwrap is safe
            .rotate_left((a.wrapping_add(b) % word::BITS as Word).try_into().unwrap());

        b = key_as_words[key_as_words_index];

        expanded_key_index = (expanded_key_index + 1) % expanded_key_table::SIZE;
        key_as_words_index = (key_as_words_index + 1) % key_as_words::SIZE;
    }

    key_table
}
