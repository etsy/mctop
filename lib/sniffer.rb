require 'pcap'
require 'thread'

class MemcacheSniffer
  HEADER = "CCnCCnNNQ"
  FIELDS = [:magic, :opcode, :keylen, :extlen, :datatype, :status, :bodylen, :opaque, :cas]
  attr_accessor :metrics, :semaphore

  def initialize(config)
    @source  = config[:nic]
    @port    = config[:port]
    @binary  = config[:binary]

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

    cap.setfilter("port #{@port}")
    cap.loop do |packet|
      @metrics[:stats] = cap.stats

      if @binary
        # Assume the header starts at the first 0x81 we see.
        header_start = (packet.raw_data.force_encoding("BINARY") =~ Regexp.new("\x81", nil, 'n'))
        if header_start
          response = parse_binary(packet.raw_data[header_start..-1])
          # See that we parsed it correctly.
          if response[:magic] == 0x81 && response[:opcode] <= 26 && response[:datatype] == 0
            metric(response[:key], response[:bodylen])
          end
        end
      else
        # parse key name, and size from VALUE responses
        if packet.raw_data =~ /VALUE (\S+) \S+ (\S+)/
          key   = $1
          bytes = $2
        end

        metric(key, bytes)
      end

      break if @done
    end

    cap.close
  end

  def metric(key, bytes)
    @semaphore.synchronize do
      if @metrics[:calls].has_key?(key)
        @metrics[:calls][key] += 1
      else
        @metrics[:calls][key] = 1
      end

      @metrics[:objsize][key] = bytes.to_i
    end
  end

  def parse_binary(data)
    response = Hash[FIELDS.zip(data[0..23].unpack(HEADER))]
    index = 24
    if response[:extlen] != 0
      response[:extras] = data[index..(index + response[:extlen])]
      index += response[:extlen]
    end

    if response[:keylen] != 0
      response[:key] = data[index..(index + response[:keylen])]
      index += response[:keylen]
    end

    if response[:bodylen] != 0
      response[:body] = data[index..(index + response[:bodylen])]
      index += response[:bodylen]
    end

    response
  end

  def done
    @done = true
  end
end
