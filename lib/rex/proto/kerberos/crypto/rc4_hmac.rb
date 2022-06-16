# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Crypto
        class Rc4Hmac

          def string_to_key(password, salt, iterations)
            raise ::RuntimeError, 'Iterations not supported for DES3' unless iterations == nil
            raise ::RuntimeError, 'Salt not supported for DES3' unless iterations == nil
            # Salt is unused in Rc4
            unicode_password = Rex::Text.to_unicode(password)
            password_digest = OpenSSL::Digest.digest('MD4', unicode_password)

            password_digest
          end
          
          # Decrypts the cipher using RC4-HMAC schema
          #
          # @param cipher [String] the data to decrypt
          # @param key [String] the key to decrypt
          # @param msg_type [Integer] the message type
          # @param confounder [String] Optionally force the confounder to a specific value
          # @return [String] the decrypted cipher
          # @raise [Rex::Proto::Kerberos::Model::Error::KerberosError] if decryption doesn't succeed
          def decrypt(cipher, key, msg_type)
            unless cipher && cipher.length > 16
              raise ::RuntimeError, 'RC4-HMAC decryption failed'
            end

            checksum = cipher[0, 16]
            data = cipher[16, cipher.length - 1]

            k1 = OpenSSL::HMAC.digest('MD5', key, [msg_type].pack('V'))
            k3 = OpenSSL::HMAC.digest('MD5', k1, checksum)

            cipher = OpenSSL::Cipher.new('rc4')
            cipher.decrypt
            cipher.key = k3
            decrypted = cipher.update(data) + cipher.final

            if OpenSSL::HMAC.digest('MD5', k1, decrypted) != checksum
              raise ::Rex::Proto::Kerberos::Model::Error::KerberosError, 'RC4-HMAC decryption failed, incorrect checksum verification'
            end

            # Expect the first 8 bytes to be the confounder
            raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'EncryptedData failed to decrypt' if decrypted.length < 8

            # Skip the confounder when returning
            decrypted[8,decrypted.length]
          end

          # Encrypts the cipher using RC4-HMAC schema
          #
          # @param data [String] the data to encrypt
          # @param key [String] the key to encrypt
          # @param msg_type [Integer] the message type
          # @return [String] the encrypted data
          def encrypt(data, key, msg_type, confounder=nil)
            k1 = OpenSSL::HMAC.digest('MD5', key, [msg_type].pack('V'))

            confounder = Rex::Text::rand_text(8) if confounder == nil
            data_encrypt = confounder + data

            checksum = OpenSSL::HMAC.digest('MD5', k1, data_encrypt)

            k3 = OpenSSL::HMAC.digest('MD5', k1, checksum)

            cipher = OpenSSL::Cipher.new('rc4')
            cipher.encrypt
            cipher.key = k3
            encrypted = cipher.update(data_encrypt) + cipher.final

            res = checksum + encrypted
            res
          end
        end
      end
    end
  end
end
