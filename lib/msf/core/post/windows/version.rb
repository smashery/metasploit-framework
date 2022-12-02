# -*- coding: binary -*-

module Msf::Post::Windows::Version

  def initialize(info = {})
    super(
      update_info(
        info,
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_railgun_api
            ]
          }
        }
      )
    )
  end

  def get_version_info
    if session.type == 'meterpreter'
      result = session.railgun.ntdll.RtlGetVersion(input_os_version_info_ex)
      os_version_info_ex = unpack_version_info(result['VersionInformation'])
      major = os_version_info_ex[1]
      minor = os_version_info_ex[2]
      build = os_version_info_ex[3]
      service_pack = os_version_info_ex[6]
      product_type = os_version_info_ex[9]

      Msf::WindowsVersion.new(major, minor, build, service_pack, product_type)
    else
    end
  end

  private

  def empty_os_version_info_ex
    result = [0,
     0,
     0,
     0,
     0,
     "",
     0,
     0,
     0,
     0,
     0
    ]
  end

  def pack_version_info(info)
    info.pack('VVVVVa256vvvCC')
  end

  def unpack_version_info(bytes)
    bytes.unpack('VVVVVa256vvvCC')
  end

  def input_os_version_info_ex
    input = empty_os_version_info_ex
    size = pack_version_info(input).size
    input[0] = size

    pack_version_info(input)
  end
end
