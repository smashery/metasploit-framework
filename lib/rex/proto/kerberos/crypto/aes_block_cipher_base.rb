# -*- coding: binary -*-
require 'rex/text'

module Rex
  module Proto
    module Kerberos
      module Crypto
        class AesBlockCipherBase < BlockCipherBase
          # Base class for AES encryption classes

          BLOCK_SIZE = 16
          PADDING_SIZE = 1
          MAC_SIZE = 12
          HASH_FUNCTION = 'SHA1'

          # Subclasses must also define ENCRYPT_CIPHER_NAME and DECRYPT_CIPHER_NAME
      
          def string_to_key(string, salt, iterations)
            iterations = 4096 if iterations == nil
            seed = OpenSSL::KDF.pbkdf2_hmac(string, salt: salt, iterations: iterations, length: self.class::SEED_SIZE, hash: HASH_FUNCTION)
            tkey = random_to_key(seed)
            derive(tkey, 'kerberos'.encode('utf-8'))
          end
      
          def encrypt_basic(plaintext, key)
            raise RuntimeError, 'Ciphertext too short' if plaintext.length < BLOCK_SIZE

            cipher = OpenSSL::Cipher.new(self.class::ENCRYPT_CIPHER_NAME)
            cipher.encrypt
            cipher.key = key
            cipher.padding = 0

            padded = pad_with_zeroes(plaintext, BLOCK_SIZE)
            ciphertext = cipher.update(padded) + cipher.final
            if plaintext.length > BLOCK_SIZE
              # Swap the last two ciphertext blocks and truncate the
              # final block to match the plaintext length.
              last_block_length = plaintext.length % BLOCK_SIZE
              last_block_length = BLOCK_SIZE if last_block_length == 0
              ciphertext = ciphertext[0, ciphertext.length - 32] + ciphertext[-BLOCK_SIZE, BLOCK_SIZE] + ciphertext[-32, last_block_length]
            end

            ciphertext
          end
      
          def decrypt_basic(ciphertext, key)
            raise RuntimeError, 'Ciphertext too short' if ciphertext.length < BLOCK_SIZE

            cipher = OpenSSL::Cipher.new(self.class::DECRYPT_CIPHER_NAME)
            cipher.decrypt
            cipher.key = key
            cipher.padding = 0

            if ciphertext.length == BLOCK_SIZE
              return cipher.update(ciphertext) + cipher.final
            end

            # Split the ciphertext into blocks.  The last block may be partial.
            block_chunks = ciphertext.unpack('C*').each_slice(BLOCK_SIZE).to_a
            last_block_length = block_chunks[-1].length

            # CBC-decrypt all but the last two blocks.
            prev_chunk = [0] * BLOCK_SIZE
            plaintext_arr = []
            block_chunks.slice(0..-3).each do |chunk|
              decrypted = cipher.update(chunk.pack('C*')) + cipher.final
              decrypted_arr = decrypted.unpack('C*')
              plaintext_arr += xor_bytes(decrypted_arr, prev_chunk)
              prev_chunk = chunk
            end

            # Decrypt the second-to-last cipher block.  The left side of
            # the decrypted block will be the final block of plaintext
            # xor'd with the final partial cipher block; the right side
            # will be the omitted bytes of ciphertext from the final
            # block.
            decrypted = cipher.update(block_chunks[-2].pack('C*')) + cipher.final
            decrypted_arr = decrypted.unpack('C*')
            last_plaintext_arr = xor_bytes(decrypted_arr[0, last_block_length], block_chunks[-1])
            omitted_arr = decrypted_arr[last_block_length, decrypted.length]

            # Decrypt the final cipher block plus the omitted bytes to get
            # the second-to-last plaintext block.

            decrypted = cipher.update((block_chunks[-1] + omitted_arr).pack('C*'))
            decrypted_arr = decrypted.unpack('C*')
            plaintext_arr += xor_bytes(decrypted_arr, prev_chunk)
            (plaintext_arr + last_plaintext_arr).pack('C*')
          end

          private

          def xor_bytes(l1,l2)
            result = []
            l1.zip(l2).each do |b1,b2|
              if b1 != nil && b2 != nil
                result.append((b1^b2))
              end
            end

            result
          end
        end
      end
    end
  end
end
