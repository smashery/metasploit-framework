# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Crypto
        module DesCbcMd5
          HASH_LENGTH = 16
          CONFOUNDER_LENGTH = 8
          # Decrypts the cipher using DES-CBC-MD5 schema
          #
          # @param cipher [String] the data to decrypt
          # @param key [String] the key to decrypt
          # @return [String] the decrypted cipher
          # @raise [RuntimeError] if decryption doesn't succeed
          def decrypt_des_cbc_md5(cipher, key)
            print_line("Decrypting DES CBC")
            unless cipher && cipher.length > CONFOUNDER_LENGTH + HASH_LENGTH
              raise ::RuntimeError, 'DES-CBC decryption failed'
            end

            cipher = OpenSSL::Cipher.new('des-cbc')
            cipher.decrypt
            cipher.key = key
            decrypted = cipher.update(data) + cipher.final

            confounder = decrypted[0, CONFOUNDER_LENGTH]
            checksum = decrypted[CONFOUNDER_LENGTH, HASH_LENGTH]
            plaintext = decrypted[CONFOUNDER_LENGTH + HASH_LENGTH, decrypted.length]
            hashed_data = confounder + '\x00' * HASH_LENGTH + plaintext

            hash_fn = OpenSSL::Digest.new('MD5')

            if hash_fn.digest(hashed_data) != checksum
              raise ::RuntimeError, 'DES-CBC decryption failed, incorrect checksum verification'
            end

            decrypted
          end

          # Pads the provided data to a multiple of block_length
          # Zeroes are added at the end
          def pad_with_zeroes(data, block_length)
            pad_length = block_length - (data.length % block_length)
            pad_length %= block_length # In case it's a perfect multiple, do no padding
            return data + '\x00' * pad_length
          end

          # Encrypts the cipher using DES-CBC-MD5 schema
          #
          # @param data [String] the data to encrypt
          # @param key [String] the key to encrypt
          # @return [String] the encrypted data
          def encrypt_des_cbc_md5(data, key)
            print_line("Encrypting DES CBC")
            confounder = Rex::Text::rand_text(CONFOUNDER_LENGTH)
            padded_data = pad_with_zeroes(data, BLOCK_LENGTH)
            hashed_data = confounder + '\x00' * HASH_LENGTH + padded_data
            hash_fn = OpenSSL::Digest.new('MD5')
            checksum = hash_fn.digest(hashed_data)

            raise ::RuntimeError, 'Invalid checksum size' unless checksum.length == HASH_LENGTH

            plaintext = confounder + checksum + padded_data

            cipher = OpenSSL::Cipher.new('des-cbc')
            cipher.encrypt
            cipher.key = key
            encrypted = cipher.update(data_encrypt) + cipher.final

            encrypted
          end
        end
      end
    end
  end
end
