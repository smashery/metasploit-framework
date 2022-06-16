# -*- coding: binary -*-

require 'rex/text'

module Rex
  module Proto
    module Kerberos
      module Crypto
        class Aes128CtsSha1 < AesBlockCipherBase
          SEED_SIZE = 16
          ENCRYPT_CIPHER_NAME = 'aes-128-cbc'
          DECRYPT_CIPHER_NAME = 'aes-128-ecb'
        end
      end
    end
  end
end
