require 'spec_helper'
require 'metasploit/framework/login_scanner/kerberos'

RSpec.describe Metasploit::Framework::LoginScanner::Kerberos do
  let(:server_name) { 'demo.local_server' }

  subject(:kerberos_scanner) do
    described_class.new({ server_name: server_name })
  end

  let(:mock_credential) do
    Metasploit::Framework::Credential.new(
      public: 'mock_public',
      private: 'mock_private',
      realm: 'DEMO.LOCAL'
    )
  end

  let(:expected_tgt_request) do
    {
      server_name: 'demo.local_server',
      client_name: 'mock_public',
      password: 'mock_private',
      realm: 'DEMO.LOCAL'
    }
  end

  let(:tgt_response_no_preauth_required) do
    ::Msf::Exploit::Remote::Kerberos::Model::Tgt.new(
      as_rep: instance_double(::Rex::Proto::Kerberos::Model::EncKdcResponse),
      preauth_required: true
    )
  end

  let(:tgt_response_success) do
    Msf::Exploit::Remote::Kerberos::Model::Tgt.new(
      as_rep: instance_double(::Rex::Proto::Kerberos::Model::KdcResponse),
      preauth_required: false
    )
  end

  let(:tgt_response_account_disabled) do
    ::Rex::Proto::Kerberos::Model::Error::KerberosError.new(
      error_code: ::Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_CLIENT_REVOKED
    )
  end

  let(:tgt_response_account_unknown) do
    ::Rex::Proto::Kerberos::Model::Error::KerberosError.new(
      error_code: ::Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_C_PRINCIPAL_UNKNOWN
    )
  end

  let(:tgt_response_preauth_failed) do
    ::Rex::Proto::Kerberos::Model::Error::KerberosError.new(
      error_code: ::Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_PREAUTH_FAILED
    )
  end

  it_behaves_like 'Metasploit::Framework::LoginScanner::Base', has_realm_key: true, has_default_realm: true

  context '#attempt_login' do
    context 'when the login does not require preauthentication' do
      before(:each) do
        allow(subject).to receive(:send_request_tgt).with(expected_tgt_request).and_return(tgt_response_no_preauth_required)
      end

      it 'returns the correct login status' do
        result = subject.attempt_login(mock_credential)

        # Note: Both correct login and no_preauth_required login attempts will be successful.
        expect(result.status).to eq(Metasploit::Model::Login::Status::SUCCESSFUL)
        expect(result.proof).to eq(tgt_response_no_preauth_required)
      end
    end

    context 'when the preauthentication login is successful' do
      before(:each) do
        allow(subject).to receive(:send_request_tgt).with(expected_tgt_request).and_return(tgt_response_success)
      end

      it 'returns the correct login status' do
        result = subject.attempt_login(mock_credential)

        # Note: Both correct login and no_preauth_required login attempts will be successful.
        expect(result.status).to eq(Metasploit::Model::Login::Status::SUCCESSFUL)
        expect(result.proof).to eq(tgt_response_success)
      end
    end

    context 'when the account is locked out' do
      before(:each) do
        allow(subject).to receive(:send_request_tgt).with(expected_tgt_request).and_raise(tgt_response_account_disabled)
      end

      it 'returns the correct login status' do
        result = subject.attempt_login(mock_credential)

        expect(result.status).to eq(Metasploit::Model::Login::Status::DISABLED)
        expect(result.proof.error_code).to eq(::Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_CLIENT_REVOKED)
      end
    end

    context 'when the principal is unknown' do
      before(:each) do
        allow(subject).to receive(:send_request_tgt).with(expected_tgt_request).and_raise(tgt_response_account_unknown)
      end

      it 'returns the correct login status' do
        result = subject.attempt_login(mock_credential)

        expect(result.status).to eq(Metasploit::Model::Login::Status::INCORRECT_PUBLIC_PART)
        expect(result.proof.error_code).to eq(::Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_C_PRINCIPAL_UNKNOWN)
      end
    end

    context 'when the password is incorrect' do
      before(:each) do
        allow(subject).to receive(:send_request_tgt).with(expected_tgt_request).and_raise(tgt_response_preauth_failed)
      end

      it 'returns the correct error code' do
        result = subject.attempt_login(mock_credential)

        expect(result.status).to eq(Metasploit::Model::Login::Status::INCORRECT)
        expect(result.proof.error_code).to eq(::Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_PREAUTH_FAILED)
      end
    end
  end
end
