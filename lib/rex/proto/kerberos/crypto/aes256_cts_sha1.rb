# -*- coding: binary -*-

require 'rex/text'

module Rex
  module Proto
    module Kerberos
      module Crypto
        class Aes256CtsSha1 < AesBlockCipherBase
          SEED_SIZE = 32
          ENCRYPT_CIPHER_NAME = 'aes-256-cbc'
          DECRYPT_CIPHER_NAME = 'aes-256-ecb'
        end
      end
    end
  end
end
