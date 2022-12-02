# -*- coding: binary -*-
module Msf
  #
  # Represents the version of a Windows operating system
  #
  class WindowsVersion

    VER_NT_WORKSTATION = 1
    VER_NT_DOMAIN_CONTROLLER = 2
    VER_NT_SERVER = 3

    class MajorRelease

      def initialize(name, enum)
        @name = name
        @enum = enum
      end

      def to_s
        @name
      end

      def >(other)
        @enum > other.enum
      end

      def <(other)
        @enum < other.enum
      end

      def ==(other)
        @enum == other.enum
      end

      def >=(other)
        @enum >= other.enum
      end

      def <=(other)
        @enum <= other.enum
      end

      attr_reader :name, :enum

      NT351 = MajorRelease.new("Windows NT 3.51", 1)
      Win95 = MajorRelease.new("Windows 95",2)
      Win98 = MajorRelease.new("Windows 98",3)
      WinME = MajorRelease.new("Windows ME",4)

      XP = MajorRelease.new("Windows XP",5)
      Server2003 = MajorRelease.new("Windows Server 2003",5)

      Vista = MajorRelease.new("Windows Vista",6)
      Server2008 = MajorRelease.new("Windows Server 2008",6)
      
      Win7 = MajorRelease.new("Windows 7",7)
      Server2008R2 = MajorRelease.new("Windows 2008 R2",7)

      Win8 = MajorRelease.new("Windows 8",8)
      Server2012 = MajorRelease.new("Windows Server 2012",8)

      Win81 = MajorRelease.new("Windows 8.1",9)
      Server2012R2 = MajorRelease.new("Windows Server 2012 R2",9)

      Win10Plus = MajorRelease.new("Windows 10+",10)
      Server2016Plus = MajorRelease.new("Windows Server 2016+",10)
    end

    def initialize(major, minor, build, service_pack, product_type)
      self.major = major
      self.minor = minor
      self.build = build
      self.service_pack = service_pack
      self.product_type = product_type
    end

    def build_number
      Rex::Version.new("#{major}.#{minor}.#{build}.#{service_pack}")
    end

    def is_windows_server
      self.product_type != VER_NT_WORKSTATION
    end

    def is_domain_controller
      self.product_type == VER_NT_DOMAIN_CONTROLLER
    end

    def major_release
      if self.major == 5
        if self.minor == 1
          return MajorRelease::XP
        elsif self.minor == 2
          return MajorRelease::Server2003 if is_windows_server
          return MajorRelease::XP
        end
      elsif self.major == 6
        if self.minor == 0
          return MajorRelease::Server2008 if is_windows_server
          return MajorRelease::Vista
        elsif self.minor == 1
          return MajorRelease::Server2008R2 if is_windows_server
          return MajorRelease::Server2008R2
        elsif self.minor == 2
          return MajorRelease::Server2008R2 if is_windows_server
          return MajorRelease::Server2008R2
        elsif self.minor == 3
          return MajorRelease::Server2008R2 if is_windows_server
          return MajorRelease::Server2008R2
        end
      elsif self.major == 10
        if self.minor == 0
          return MajorRelease::Server2016Plus if is_windows_server
          return MajorRelease::Win10Plus
        end
      end
      return nil
    end

    def product_name
      result = "Unknown Windows version: #{self.major}.#{self.minor}.#{self.build}"
      result = major_release.name unless major_release.nil?
      result = "#{result} Service Pack #{self.service_pack}" if self.service_pack != 0
      result = "#{result} Build #{self.build}" if major_release >= MajorRelease::Win10Plus

      result
    end

    def to_s
      product_name
    end

    XP_SP0 = Rex::Version.new('5.1.2600.0')
    XP_SP1 = Rex::Version.new('5.1.2600.1')
    XP_SP2 = Rex::Version.new('5.1.2600.2')
    XP_SP3 = Rex::Version.new('5.1.2600.3')
    Server2003_SP0 = Rex::Version.new('5.2.3790.0')
    Server2003_SP1 = Rex::Version.new('5.2.3790.1')
    Server2003_SP2 = Rex::Version.new('5.2.3790.2')
    Vista_SP0 = Server2008_SP0 = Rex::Version.new('6.0.6000.0')
    Vista_SP1 = Server2008_SP1 = Rex::Version.new('6.0.6001.1')
    Vista_SP2 = Server2008_SP2 = Rex::Version.new('6.0.6002.2')
    Win7_SP0 = Server2008_R2_SP0 = Rex::Version.new('6.1.7600.0')
    Win7_SP1 = Server2008_R2_SP1 = Rex::Version.new('6.1.7601.1')
    Win8 = Server2012 = Rex::Version.new('6.2.9200.0')
    Win81 = Server2012_R2 = Rex::Version.new('6.3.9600.0')
    Win10_1507 = Win10_InitialRelease = Rex::Version.new('10.0.10240.0')
    Win10_1511 = Rex::Version.new('10.0.10586.0')
    Win10_1607 = Server2016 = Rex::Version.new('10.0.14393.0')
    Win10_1703 = Rex::Version.new('10.0.15063.0')
    Win10_1709 = Rex::Version.new('10.0.16299.0')
    Win10_1803 = Rex::Version.new('10.0.17134.0')
    Win10_1809 = Server2019 = Rex::Version.new('10.0.17763.0')
    Win10_1903 = Rex::Version.new('10.0.18362.0')
    Win10_1909 = Rex::Version.new('10.0.18363.0')
    Win10_2004 = Rex::Version.new('10.0.19041.0')
    Win10_20H2 = Rex::Version.new('10.0.19042.0')
    Win10_21H1 = Rex::Version.new('10.0.19043.0')
    Win10_21H2 = Rex::Version.new('10.0.19044.0')
    Win10_22H2 = Rex::Version.new('10.0.19044.0')
    Server2022 = Rex::Version.new('10.0.20348.0')
    Win11_21H2 = Rex::Version.new('10.0.22000.0')
    Win11_22H2 = Rex::Version.new('10.0.22621.0')

    
    attr_accessor :major, :minor, :build, :service_pack, :product_type
  end
end
