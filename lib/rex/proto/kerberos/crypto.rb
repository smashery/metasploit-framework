# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Crypto

        include Rex::Proto::Kerberos::Crypto::Rc4Hmac
        include Rex::Proto::Kerberos::Crypto::DesCbcMd5
        include Rex::Proto::Kerberos::Crypto::RsaMd5

        DES_CBC_MD5 = 3
        RSA_MD5 = 7
        RC4_HMAC = 23
        ENC_KDC_REQUEST_BODY = 10
        ENC_AS_RESPONSE = 8
        ENC_TGS_RESPONSE = 9
      end
    end
  end
end
