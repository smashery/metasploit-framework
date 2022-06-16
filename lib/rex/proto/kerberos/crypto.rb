# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Crypto

        # Checksums
        RSA_MD5 = 7

        # Encryptors
        DES_CBC_MD5 = 3
        DES3_CBC_SHA1 = 16
        AES128 = 17
        AES256 = 18
        RC4_HMAC = 23

        def get_kerberos_encryptor(etype)
          case etype
          when DES_CBC_MD5
            Rex::Proto::Kerberos::Crypto::DesCbcMd5.new
          when DES3_CBC_SHA1
            Rex::Proto::Kerberos::Crypto::Des3CbcSha1.new
          when RC4_HMAC
            Rex::Proto::Kerberos::Crypto::Rc4Hmac.new
          else
            raise ::NotImplementedError, 'EncryptedDat schema is not supported'
          end
        end

        ENC_KDC_REQUEST_BODY = 10
        ENC_AS_RESPONSE = 8
        ENC_TGS_RESPONSE = 9
      end
    end
  end
end
