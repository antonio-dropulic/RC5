//! Constants and types used in the implementation of the RC5-32/12/16 cipher. For further reference check the [RC5 paper] and the
//! [Naming][crate::core#naming] section in the module documentation.
//!
//! [RC5 paper]: https://www.grc.com/r&d/rc5.pdf

// TODO: doc
macro_rules! impl_rc5 {
    (w = $word:ty, r = $rounds:expr, b = $key_size:expr) => {
        /// Unsized integer type. Word size (w) is the size of Word in BITS.
        /// Allowed values of of w are 16, 32, 64. In other words, allowed word types are
        /// u16, u32, u64.
        pub type Word = $word;
        /// Number of rounds. Allowed values 0-255.
        pub const ROUNDS: u8 = $rounds;
        /// Size of key in bytes. Allowed values 0-255.
        const KEY_SIZE: u8 = $key_size;

        pub mod word {
            use super::Word;
            pub const BITS: u8 = Word::BITS as u8;
            pub const BYTES: usize = Word::BITS as usize / 8;

            static_assertions::const_assert!(BITS == 16 || BITS == 32 || BITS == 64);

            pub const fn p() -> Word {
                // does not overflow
                #[allow(overflowing_literals)]
                match Word::BITS {
                    16 => 0xb7e1,
                    32 => 0xb7e15163,
                    64 => 0xb7e151628aed2a6b,
                    _ => panic!("Only allowed values of w are 16, 32, 64"),
                }
            }

            pub const fn q() -> Word {
                // does not overflow
                #[allow(overflowing_literals)]
                match Word::BITS {
                    16 => 0x9e37,
                    32 => 0x9e3779b9,
                    64 => 0x9e3779b97f4a7c15,
                    _ => panic!("Only allowed values of w are 16, 32, 64"),
                }
            }
        }

        pub type Block = [u8; block::BYTES];
        pub mod block {
            use super::word;
            pub const BYTES: usize = word::BYTES * 2;
        }

        pub type Key = [u8; key::BYTES];
        pub mod key {
            use super::KEY_SIZE;
            pub const BYTES: usize = KEY_SIZE as usize;
        }

        pub type ExpandedKeyTable = [Word; expanded_key_table::SIZE];
        pub mod expanded_key_table {
            use super::ROUNDS;

            pub const SIZE: usize = 2 * (ROUNDS as usize + 1);
        }

        pub type KeyAsWords = [Word; key_as_words::SIZE];
        pub mod key_as_words {
            use super::{key, word};

            // TODO: div_ceil(key::BYTES / word::BYTES), why is this correct
            pub const SIZE: usize = (key::BYTES + word::BYTES - 1) / word::BYTES;
        }
    };
}

// TODO: what are the nominal values?
// we can just use the macro
// this requires a macro in the block cipher as well.
// we can try to pass in generics

impl_rc5! {w = u32, r = 12, b = 16}
