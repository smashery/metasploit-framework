# -*- coding:binary -*-
require 'spec_helper'

RSpec.describe Rex::Proto::Kerberos::Crypto::Des3CbcSha1 do
  subject(:encryptor) do
    described_class.new
  end

  it 'Key generation passes RFC 3961 test case 1' do
    password = 'password'
    salt = 'ATHENA.MIT.EDUraeburn'

    des_key = encryptor.string_to_key(password, salt)
    expect(des_key).to eq(["850bb51358548cd05e86768c313e3bfef7511937dcf72c3e"].pack("H*"))
  end

  it 'Key generation passes RFC 3961 test case 2' do
    password = 'potatoe'
    salt = 'WHITEHOUSE.GOVdanny'

    des_key = encryptor.string_to_key(password, salt)
    expect(des_key).to eq(["dfcd233dd0a43204ea6dc437fb15e061b02979c1f74f377a"].pack("H*"))
  end

  it 'Key generation passes RFC 3961 test case 3' do
    password = 'penny'
    salt = 'EXAMPLE.COMbuckaroo'

    des_key = encryptor.string_to_key(password, salt)
    expect(des_key).to eq(["6d2fcdf2d6fbbc3ddcadb5da5710a23489b0d3b69d5d9d4a"].pack("H*"))
  end

  it 'Key generation passes RFC 3961 test case 4' do
    password = "\u00df"
    salt = "ATHENA.MIT.EDUJuri\u0161i\u0107"

    des_key = encryptor.string_to_key(password, salt)
    expect(des_key).to eq(["16d5a40e1ce3bacb61b9dce00470324c831973a7b952feb0"].pack("H*"))
  end

  it 'Key generation passes RFC 3961 test case 5' do
    password = "\u{1D11E}"
    salt = 'EXAMPLE.COMpianist'

    des_key = encryptor.string_to_key(password, salt)
    expect(des_key).to eq(["85763726585dbc1cce6ec43e1f751f07f1c4cbb098f40b19"].pack("H*"))
  end
end
