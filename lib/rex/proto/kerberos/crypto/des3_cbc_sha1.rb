# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Crypto
        class Des3CbcSha1
          HASH_LENGTH = 16
          BLOCK_LENGTH = 8
          SEED_SIZE = 21

          def string_to_key(string, salt)
            print("Salt is #{salt}\n")
            utf8_encoded = (string + salt).encode('UTF-8').bytes
            k = random_to_key(nfold(utf8_encoded, 21))
            k = k.pack('C*')
            result_arr = derive(k, 'kerberos'.encode('UTF-8').bytes, BLOCK_LENGTH, SEED_SIZE)

            result_arr.pack('C*')
          end

          # Decrypts the cipher using DES3-CBC-SHA1 schema
          #
          # @param cipher [String] the data to decrypt
          # @param key [String] the key to decrypt
          # @param msg_type [Integer] ignored for this algorithm
          # @return [String] the decrypted cipher
          # @raise [RuntimeError] if decryption doesn't succeed
          def decrypt(cipher, key, msg_type)
            cipher = OpenSSL::Cipher.new('des-ede3-cbc')
            cipher.decrypt
            cipher.key = key
            decrypted = cipher.update(data)

            decrypted
          end

          # Encrypts the cipher using DES3-CBC-SHA1 schema
          #
          # @param data [String] the data to encrypt
          # @param key [String] the key to encrypt
          # @return [String] the encrypted data
          def encrypt(data, key)
            cipher = OpenSSL::Cipher.new('des-ede3-cbc')
            cipher.encrypt
            cipher.key = key
            encrypted = cipher.update(data)

            encrypted
          end

          private
          
          def nfold(ba, nbytes)
            # Convert bytearray to a string of length nbytes using the RFC 3961 nfold
            # operation.
          
            # Rotate the bytes in ba to the right by nbits bits.
            def rotate_right(ba, nbits)
              nbytes, remain = (nbits / 8) % ba.length, nbits % 8
              ba.length.times.map do |i|
                (ba[i-nbytes] >> remain) | ((ba[i-nbytes-1] << (8-remain)) & 0xff)
              end
            end
          
            # Add equal-length strings together with end-around carry.
            def add_ones_complement(arr1, arr2)
              n = arr1.length
              # Add all pairs of numbers
              v = arr1.zip(arr2).map { |a,b| a+b}
              
              while v.any? { |x| x > 0xff }
                v = v.length.times.map {|i| (v[i-n+1]>>8) + (v[i]&0xff)}
              end
          
              v
            end
          
            # Let's work in terms of numbers rather than strings
            slen = ba.length
            lcm = nbytes * slen / nbytes.gcd(slen)
            bigstr = []
            num_copies = lcm / slen
            num_copies.times do |i|
              bigstr += rotate_right(ba, 13 * i)
            end
            
            result = bigstr.each_slice(nbytes).reduce {|l1,l2| add_ones_complement(l1,l2) }

            result
          end

          def random_to_key(seed)
            print("Seed is #{seed}\n")
            def expand(seed)
              def parity(b)
                # Return b with the low-order bit set to yield odd parity.
                b &= ~1
                b | (b.digits(2).count(1) + 1) % 2
              end
              
              raise ::RuntimeError unless seed.length == 7
        
              firstbytes = seed.map {|b| parity(b & ~1)}
              tmp = 7.times.map { |i| (seed[i] & 1) << i+1 }
              lastbyte = parity(tmp.sum)
              keybytes = firstbytes + [lastbyte]
              if _is_weak_des_key(keybytes)
                keybytes[7] = keybytes[7] ^ 0xF0
              end
              
              keybytes
            end
        
            raise ::RuntimeError unless seed.length == 21
            
            subkeys = seed.each_slice(7).map { |slice| expand(slice) }
            subkeys.flatten
          end

          def derive(key_arr, constant, blocksize, seedsize)
            # RFC 3961 only says to n-fold the constant only if it is
            # shorter than the cipher block size.  But all Unix
            # implementations n-fold constants if their length is larger
            # than the block size as well, and n-folding when the length
            # is equal to the block size is a no-op.
            plaintext_arr = nfold(constant, blocksize)
            print("plaintext_arr is #{plaintext_arr}\n")
            rndseed = []
            while rndseed.length < seedsize do
              plaintext_str = plaintext_arr.pack('C*')
              ciphertext_str = encrypt(plaintext_str, key_arr)
              ciphertext_arr = ciphertext_str.unpack('C*')
              print("ciphertext_arr is #{ciphertext_arr}\n")
              rndseed += ciphertext_arr
              plaintext_arr = ciphertext_arr
            end

            random_to_key(rndseed[0,seedsize])
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
