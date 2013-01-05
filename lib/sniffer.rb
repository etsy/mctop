require 'pcap'
require 'thread'

class MemcacheSniffer
  HEADER = "CCnCCnNNQ"
  FIELDS = [:magic, :opcode, :keylen, :extlen, :datatype, :status, :bodylen, :opaque, :cas]
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

    cap.setfilter("port #{@port}")
    cap.loop do |packet|
      @metrics[:stats] = cap.stats

      if @config[:binary]
        response = parse_binary(packet.raw_data)
        # Response
        if response[:magic] == 0x81
          metric(response[:key], response[:bodylen])
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
    response = {}
    index = 0
    header = Hash[FIELDS.zip(data[0..23].unpack(HEADER))]
    index = 24
    if header[:extlen] != 0
      response[:extras] = data[index..(index + header[:extlen])]
      index += header[:extlen]
    end

    if header[:keylen] != 0
      response[:key] = data[index..(index + header[:keylen])]
      index += header[:keylen]
    end

    if header[:bodylen] != 0
      response[:body] = data[index..(index + header[:bodylen])]
      index += header[:bodylen]
    end
    
    response
  end

  def done
    @done = true
  end
end
