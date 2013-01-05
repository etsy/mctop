require 'pcap'
require 'thread'

class MemcacheSniffer
  # The following constants are adapted from
  # https://github.com/mperham/dalli/blob/master/lib/dalli/server.rb
  HEADER = "CCnCCnNNQ"
  FIELDS = [:magic, :opcode, :keylen, :extlen, :datatype, :status, :bodylen, :opaque, :cas]

  MAGIC = {
    0x80 => 'Request',
    0x81 => 'Response'
  }

  RESPONSE_CODES = {
    0 => 'No error',
    1 => 'Key not found',
    2 => 'Key exists',
    3 => 'Value too large',
    4 => 'Invalid arguments',
    5 => 'Item not stored',
    6 => 'Incr/decr on a non-numeric value',
    0x20 => 'Authentication required',
    0x81 => 'Unknown command',
    0x82 => 'Out of memory',
  }

  OPCODES = {
    :get => 0x00,
    :set => 0x01,
    :add => 0x02,
    :replace => 0x03,
    :delete => 0x04,
    :incr => 0x05,
    :decr => 0x06,
    :flush => 0x08,
    :noop => 0x0A,
    :version => 0x0B,
    :getk => 0x0C,
    :getkq => 0x0D,
    :append => 0x0E,
    :prepend => 0x0F,
    :stat => 0x10,
    :setq => 0x11,
    :addq => 0x12,
    :replaceq => 0x13,
    :deleteq => 0x14,
    :incrq => 0x15,
    :decrq => 0x16,
    :quitq => 0x17,
    :flushq => 0x18,
    :appendq => 0x19,
    :prependq => 0x1A,
    :auth_negotiation => 0x20,
    :auth_request => 0x21,
    :auth_continue => 0x22,
    :touch => 0x1C,
  }.invert

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
        # Assume the header starts at the first magic/[opcode/keylen/extlen]/datatype we see.
        header_start = (packet.raw_data.force_encoding("BINARY") =~ Regexp.new("(\x80|\x81)....\x00", nil, 'n'))
        if header_start
          data = packet.raw_data[header_start..-1]
          header = parse_header(data)
          # See that we found the right part of the packet for the header.
          if header[:opcode] && header[:opcode] <= 26
            puts data.unpack('H*').inspect, header.inspect if $dump
            response = parse_binary(header, data)
            puts response.inspect if $dump

            # TODO: We can't get the response length for GET requests yet,
            # since in binary mode the response usually doesn't include the key.
            # We'll have to track req/resp :/
            # Then break it apart into metric_key for request
            # And metric_bytes for response
            if response[:key]
              metric(response[:key].gsub("\0",'\0'), header[:bodylen])
            end
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
    return unless key && bytes
    @semaphore.synchronize do
      if @metrics[:calls].has_key?(key)
        @metrics[:calls][key] += 1
      else
        @metrics[:calls][key] = 1
      end

      @metrics[:objsize][key] = bytes.to_i
    end
  end

  def metric_key(key)
    @semaphore.synchronize do
      if @metrics[:calls].has_key?(key)
        @metrics[:calls][key] += 1
      else
        @metrics[:calls][key] = 1
      end
    end
  end

  def metric_bytes(key, bytes)
    @semaphore.synchronize do
      @metrics[:objsize][key] = bytes.to_i
    end
  end  

  def parse_header(data)
    return {} if data.size < 24

    header = Hash[FIELDS.zip(data[0..23].unpack(HEADER))]
    
    if $dump
      header[:magic_name] = MAGIC[header[:magic]]
      header[:opcode_name] = OPCODES[header[:opcode]]
      header[:status_name] = RESPONSE_CODES[header[:status]]
    end

    header
  end

  def parse_binary(header, data)
    index = 24
    response = {}

    if header[:extlen] != 0
      response[:extras] = data[index..(index + header[:extlen] - 1)]
      index += header[:extlen]
    end

    if header[:keylen] != 0
      response[:key] = data[index..(index + header[:keylen] - 1)]
      index += header[:keylen]
    end

    # We don't really care about bodies. This errors out with bad header lengths.
    # if header[:bodylen] != 0
    #   response[:body] = data[index..(index + header[:bodylen] -1)]
    #   index += header[:bodylen]
    # end

    response
  end

  def done
    @done = true
  end
end
