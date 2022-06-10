# -*- coding:binary -*-
require 'spec_helper'

RSpec.describe Rex::Proto::Kerberos::Crypto::DesCbcMd5 do
  subject(:encryptor) do
    Class.new.extend(described_class)
  end

  it 'Key generation passes RFC 3961 test case 1' do
    password = 'password'
    salt = 'ATHENA.MIT.EDUraeburn'

    des_key = encryptor.get_key_des_cbc_md5(password, salt)
    expect(des_key).to eq("\xcb\xc2\x2f\xae\x23\x52\x98\xe3")
  end

  it 'Key generation passes RFC 3961 test case 2' do
    password = 'potatoe'
    salt = 'WHITEHOUSE.GOVdanny'

    des_key = encryptor.get_key_des_cbc_md5(password, salt)
    expect(des_key).to eq("\xdf\x3d\x32\xa7\x4f\xd9\x2a\x01")
  end

  it 'Key generation passes RFC 3961 test case 3' do
    password = "\u{1D11E}"
    salt = 'EXAMPLE.COMpianist'

    des_key = encryptor.get_key_des_cbc_md5(password, salt)
    expect(des_key).to eq("\x4f\xfb\x26\xba\xb0\xcd\x94\x13")
  end

  it 'Key generation passes RFC 3961 test case 4' do
    password = "\u00df"
    salt = "ATHENA.MIT.EDUJuri\u0161i\u0107"

    des_key = encryptor.get_key_des_cbc_md5(password, salt)
    expect(des_key).to eq("\x62\xc8\x1a\x52\x32\xb5\xe6\x9d")
  end

  it 'Key generation passes RFC 3961 test case 5' do
    password = "11119999"
    salt = "AAAAAAAA"

    des_key = encryptor.get_key_des_cbc_md5(password, salt)
    expect(des_key).to eq("\x98\x40\x54\xd0\xf1\xa7\x3e\x31")
  end

  it 'Key generation passes RFC 3961 test case 6' do
    password = "NNNN6666"
    salt = "FFFFAAAA"

    des_key = encryptor.get_key_des_cbc_md5(password, salt)
    expect(des_key).to eq("\xc4\xbf\x6b\x25\xad\xf7\xa4\xf8")
  end
end
