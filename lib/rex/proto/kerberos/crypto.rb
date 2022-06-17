# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Crypto

        # Checksums
        RSA_MD5 = 7
        MD5_DES = 8
        SHA1_DES3 = 12
        SHA1_AES128 = 15
        SHA1_AES256 = 16
        HMAC_MD5 = -138

        # Encryptors
        DES_CBC_MD5 = 3
        DES3_CBC_SHA1 = 16
        AES128 = 17
        AES256 = 18
        RC4_HMAC = 23

        def get_kerberos_checksummer(ctype)
          checksummers = {
            RSA_MD5     => Rex::Proto::Kerberos::Crypto::RsaMd5Checksum,
            MD5_DES     => Rex::Proto::Kerberos::Crypto::DesCbcMd5,
            SHA1_DES3   => Rex::Proto::Kerberos::Crypto::Des3CbcSha1,
            SHA1_AES128 => Rex::Proto::Kerberos::Crypto::Aes128CtsSha1,
            SHA1_AES256 => Rex::Proto::Kerberos::Crypto::Aes256CtsSha1,
            HMAC_MD5    => Rex::Proto::Kerberos::Crypto::Rc4Hmac,
            0xffffff76  => Rex::Proto::Kerberos::Crypto::Rc4Hmac,
          }

          result = checksummers[ctype]
          raise ::NotImplementedError, 'Checksum type is not supported' if result == nil

          result.new
        end

        def get_kerberos_encryptor(etype)
          encryptors = {
            DES_CBC_MD5 =>   Rex::Proto::Kerberos::Crypto::DesCbcMd5,
            DES3_CBC_SHA1 => Rex::Proto::Kerberos::Crypto::Des3CbcSha1,
            RC4_HMAC =>      Rex::Proto::Kerberos::Crypto::Rc4Hmac,
            AES128 =>        Rex::Proto::Kerberos::Crypto::Aes128CtsSha1,
            AES256 =>        Rex::Proto::Kerberos::Crypto::Aes256CtsSha1,
          }

          result = encryptors[etype]
          raise ::NotImplementedError, 'EncryptedData schema is not supported' if result == nil

          result.new
        end

        ENC_KDC_REQUEST_BODY = 10
        ENC_AS_RESPONSE = 8
        ENC_TGS_RESPONSE = 9
      end
    end
  end
end
