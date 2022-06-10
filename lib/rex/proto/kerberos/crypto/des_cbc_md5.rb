# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Crypto
        module DesCbcMd5
          HASH_LENGTH = 16
          BLOCK_LENGTH = 8


          def get_key_des_cbc_md5(string, salt)
            reverse_this_block = false
            tempstring = [0,0,0,0,0,0,0,0]

            utf8_encoded = (string + salt).encode('UTF-8').bytes.pack('C*')

            data = pad_with_zeroes(utf8_encoded, BLOCK_LENGTH)
            data_as_blocks = data.unpack('C*')

            data_as_blocks.each_slice(BLOCK_LENGTH) do |block|
              result = []
              block.each do |byte|
                # Ignore the Most Significant Bit of each byte
                result.append(byte & 0x7F)
              end

              if reverse_this_block
                reversed = []
                result.reverse.each do |byte|
                  d = byte.digits(2)
                  d = d + [0] * (7 - d.length)
                  reversed.append(d.join('').to_i(2))
                end

                result = reversed
              end

              reverse_this_block = (not reverse_this_block)

              tempstring = XOR(tempstring,result)
            end

            paritied = addparity(tempstring)
            tempkey = paritied.pack('C*')

            if _is_weak_des_key(tempkey)
              paritied[7] = paritied[7] ^ 0xF0
              tempkey = paritied.pack('C*')
            end

            cipher = OpenSSL::Cipher.new('des-cbc')
            cipher.encrypt
            cipher.key = tempkey
            cipher.iv = tempkey

            encrypted = cipher.update(data)
            checksumkey = encrypted

            checksumkey = encrypted[-8,8]
            paritied = fixparity(checksumkey.unpack('C*'))
            checksumkey = paritied.pack('C*')
            if _is_weak_des_key(checksumkey)
              paritied[7] = paritied[7] ^ 0xF0
              checksumkey = paritied.pack('C*')
            end

            checksumkey
          end

          # Decrypts the cipher using DES-CBC-MD5 schema
          #
          # @param cipher [String] the data to decrypt
          # @param key [String] the key to decrypt
          # @return [String] the decrypted cipher
          # @raise [RuntimeError] if decryption doesn't succeed
          def decrypt_des_cbc_md5(cipher, key)
            unless cipher && cipher.length > BLOCK_LENGTH + HASH_LENGTH
              raise ::RuntimeError, 'DES-CBC decryption failed'
            end

            cipher = OpenSSL::Cipher.new('des-cbc')
            cipher.decrypt
            cipher.key = key
            decrypted = cipher.update(data) + cipher.final

            confounder = decrypted[0, BLOCK_LENGTH]
            checksum = decrypted[BLOCK_LENGTH, HASH_LENGTH]
            plaintext = decrypted[BLOCK_LENGTH + HASH_LENGTH, decrypted.length]
            hashed_data = confounder + "\x00" * HASH_LENGTH + plaintext

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
            return data + "\x00" * pad_length
          end

          # Encrypts the cipher using DES-CBC-MD5 schema
          #
          # @param data [String] the data to encrypt
          # @param key [String] the key to encrypt
          # @return [String] the encrypted data
          def encrypt_des_cbc_md5(data, key)
            confounder = Rex::Text::rand_text(BLOCK_LENGTH)
            padded_data = pad_with_zeroes(data, BLOCK_LENGTH)
            hashed_data = confounder + "\x00" * HASH_LENGTH + padded_data
            hash_fn = OpenSSL::Digest.new('MD5')
            checksum = hash_fn.digest(hashed_data)

            raise ::RuntimeError, 'Invalid checksum size' unless checksum.length == HASH_LENGTH

            plaintext = confounder + checksum + padded_data

            cipher = OpenSSL::Cipher.new('des-cbc')
            cipher.encrypt
            cipher.key = key
            encrypted = cipher.update(plaintext) + cipher.final

            encrypted
          end

          private

          def fixparity(deskey)
            temp = []
            deskey.each do |byte|
              bits = byte.digits(2).reverse
              bits.pop # Ignore the last bit, since it's a parity bit
              add_at_end = (bits.count(1) + 1) % 2
              bits.append(add_at_end)
              parity_fixed = bits.join('').to_i(2)
              temp.append(parity_fixed)
            end

            temp
          end

          def addparity(bytes)
            temp = []
            bytes.each do |byte|
              bits = byte.digits(2).reverse
              to_add = (bits.count(1) + 1) % 2
              result = (byte << 1) + to_add
              temp.append(result & 0xFF)
            end

            temp
          end

          def XOR(l1,l2)
            result = []
            l1.zip(l2).each do |b1,b2|
              if b1 != nil && b2 != nil
                result.append((b1^b2)&0b01111111)
              end
            end

            result
          end
          def _is_weak_des_key(keybytes)
            ["\x01\x01\x01\x01\x01\x01\x01\x01",
             "\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE",
             "\x1F\x1F\x1F\x1F\x0E\x0E\x0E\x0E",
             "\xE0\xE0\xE0\xE0\xF1\xF1\xF1\xF1",
             "\x01\xFE\x01\xFE\x01\xFE\x01\xFE",
             "\xFE\x01\xFE\x01\xFE\x01\xFE\x01",
             "\x1F\xE0\x1F\xE0\x0E\xF1\x0E\xF1",
             "\xE0\x1F\xE0\x1F\xF1\x0E\xF1\x0E",
             "\x01\xE0\x01\xE0\x01\xF1\x01\xF1",
             "\xE0\x01\xE0\x01\xF1\x01\xF1\x01",
             "\x1F\xFE\x1F\xFE\x0E\xFE\x0E\xFE",
             "\xFE\x1F\xFE\x1F\xFE\x0E\xFE\x0E",
             "\x01\x1F\x01\x1F\x01\x0E\x01\x0E",
             "\x1F\x01\x1F\x01\x0E\x01\x0E\x01",
             "\xE0\xFE\xE0\xFE\xF1\xFE\xF1\xFE",
             "\xFE\xE0\xFE\xE0\xFE\xF1\xFE\xF1"].include?(keybytes)
          end

        end
      end
    end
  end
end
