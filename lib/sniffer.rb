require 'pcap'
require 'thread'

class MemcacheSniffer
  attr_accessor :metrics, :semaphore

  def initialize(config)
    @source  = config[:nic]
    @port    = config[:port]

    @metrics = {}
    @metrics[:calls]   = {}
    @metrics[:objsize] = {}
    @metrics[:reqsec]  = {}
    @metrics[:bw]    = {}
    @metrics[:stats]   = { :recv => 0, :drop => 0 }

    @semaphore = Mutex.new
  end

  def start
    cap = Pcap::Capture.open_live(@source, 1500)

    @metrics[:start_time] = Time.new.to_f

    @done    = false

    lookup_magic = { 128 => 'req ', 129 => 'resp'}

    cap.setfilter("port #{@port}")
    cap.loop do |packet|
      @metrics[:stats] = cap.stats

      key = ""
      bytes = 0
      valid_parse = false

      if not packet.tcp_data.nil?

        magic = packet.tcp_data[0].unpack('C')[0]
        # binary protocol
        if magic == 128 or magic == 129
          # 1 byte magic
          magic_str = lookup_magic[magic]
          # 1 byte opcode, e.g. set or get only.. for now  0 get 1 set 2 add
          opcode = packet.tcp_data[1].unpack('C')[0]
          # 2 byte key length  reqs only...
          key_length = packet.tcp_data[2,3].unpack('n')[0]
          # 1 byte extra length
          # 1 byte data type
          # 2 byte status
          # 4 byte total body length
          total_body_length = packet.tcp_data[8,11].unpack('N')[0]
          # 14 byte opaque
          # 4 byte cas
          # ---- total 24 bytes

          # only do this if our opcode is 0x01 e.g. set
          if opcode == 1 and magic == 128
            key += packet.tcp_data[24..-1]
            # body_length - 4 bytes gives us bytes like the ascii parser. why? cas?
            bytes = total_body_length - 4
            valid_parse = true
          end
        # ascii protocol
        elsif packet.raw_data =~ /VALUE (\S+) \S+ (\S+)/
          key   = $1
          bytes = $2
          valid_parse = true
        end
        # replace non printable by ~
        unless key.nil?
          key   = key.gsub(/[^[:print:]]/, '~')
        end

        if valid_parse
          @semaphore.synchronize do
            if @metrics[:calls].has_key?(key)
              @metrics[:calls][key] += 1
            else
              @metrics[:calls][key] = 1
            end

            @metrics[:objsize][key] = bytes.to_i
          end
        end
      end

      break if @done
    end

    cap.close
  end

  def done
    @done = true
  end
end
