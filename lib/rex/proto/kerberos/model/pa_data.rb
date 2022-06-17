# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        # This class provides a representation of pre-authentication data
        # that allows login attempts if pre-authentication is required
        class PaData < Element
          # @!attribute etype_info2
          #   @return [Rex::Proto::Kerberos::Model::EtypeInfo2] A list of the supported encryption types
          attr_accessor :etype_info2

          # Decodes the Rex::Proto::Kerberos::Model::PaData from an input
          #
          # @param input [String, OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [self] if decoding succeeds
          # @raise [Rex::Proto::Kerberos::Model::Error::KerberosDecodingError] if decoding doesn't succeed
          def decode(input)
            case input
            when String
              decode_string(input)
            when OpenSSL::ASN1::ASN1Data
              decode_asn1(input)
            else
              raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'Failed to decode PAData, invalid input'
            end

            self
          end

          private

          # Decodes a Rex::Proto::Kerberos::Model::PaData from an String
          #
          # @param input [String] the input to decode from
          def decode_string(input)
            asn1 = OpenSSL::ASN1.decode(input)

            decode_asn1(asn1)
          end

          # Decodes a Rex::Proto::Kerberos::Model::PaData
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @raise [Rex::Proto::Kerberos::Model::Error::KerberosDecodingError] if decoding doesn't succeed
          def decode_asn1(input)
            input.value.each do |outer_val|
              padata_type = nil
              outer_val.value.each do |inner_val|
                case inner_val.tag
                when 1
                  padata_type = inner_val.value[0].value.to_i
                when 2
                  case padata_type
                  when 19
                    self.etype_info2 = decode_etype_info2(inner_val)
                  else
                    # Just ignore it
                  end
                else
                  raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, "Failed to decode PAData SEQUENCE (#{outer_val.tag})"
                end
              end
            end
          end

          # We only support pa-etype-info2 (value=19, per RFC4120), so let's just throw an error until we implement anything else
          def make_sure_it_is_pa_etype_info2(input)
            value = input.value[0].value.to_i
            raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'Failed to decode PAData-Value' unless value == 19
          end

          # Decodes the pa-etype-info2 from an OpenSSL::ASN1::ASN1Data
          #
          # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
          # @return [Integer]
          def decode_etype_info2(input)
            value = OpenSSL::ASN1.decode(input.value[0].value)
            Rex::Proto::Kerberos::Model::EtypeInfo2.decode(value)
          end
        end
      end
    end
  end
end
