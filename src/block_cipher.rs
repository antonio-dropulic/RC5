use cipher::consts::{U12, U16, U26, U8};

use crate::core::{decrypt_block, encrypt_block, substitute_key, ExpandedKeyTable};
use cipher::{impl_simple_block_encdec, AlgorithmName, KeyInit};
use cipher::{inout::InOut, Block, BlockCipher, KeySizeUser};

pub struct RC5_32_12_16 {
    key_table: ExpandedKeyTable<u32, U26>,
}

impl RC5_32_12_16 {
    fn encrypt_block(&self, block: InOut<'_, '_, Block<Self>>) {
        encrypt_block::<u32, U12>(block, &self.key_table);
    }

    fn decrypt_block(&self, block: InOut<'_, '_, Block<Self>>) {
        decrypt_block::<u32, U12>(block, &self.key_table);
    }
}

impl BlockCipher for RC5_32_12_16 {}

impl KeySizeUser for RC5_32_12_16 {
    type KeySize = U16;
}

impl KeyInit for RC5_32_12_16 {
    fn new(key: &cipher::Key<Self>) -> Self {
        Self {
            key_table: substitute_key::<u32, U12, U16>(key),
        }
    }
}

impl AlgorithmName for RC5_32_12_16 {
    fn write_alg_name(f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RC5-32/12/16")
    }
}

// TODO: impl by hand. Code is obfuscated. Macro undocumented.
impl_simple_block_encdec!(
    RC5_32_12_16, U8, cipher, block,
    encrypt: {
        cipher.encrypt_block(block);
    }
    decrypt: {
        cipher.decrypt_block(block);
    }
);

#[cfg(feature = "zeroize")]
impl cipher::zeroize::ZeroizeOnDrop for RC5_32_12_16 {}

#[cfg(feature = "zeroize")]
impl Drop for RC5_32_12_16 {
    fn drop(&mut self) {
        cipher::zeroize::Zeroize::zeroize(&mut self.key_table);
    }
}
