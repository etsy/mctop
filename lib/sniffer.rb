require 'pcap'
require 'thread'
#require 'logger'

class MemcacheSniffer
  attr_accessor :metrics, :semaphore, :log

  def initialize(config)
    @source  = config[:nic]
    @port    = config[:port]

    @metrics = {}
    @metrics[:deletes]   = {}
    @metrics[:sets]   = {}
    @metrics[:gets]   = {}
    @metrics[:hits]   = {}
    @metrics[:calls]   = {}
    @metrics[:objsize] = {}
    @metrics[:reqsec]  = {}
    @metrics[:bw]      = {}
    @metrics[:stats]   = { :recv => 0, :drop => 0 }

    @semaphore = Mutex.new
    #@log = Logger.new('/tmp/logfile.log')
  end

  def command(key) 
    if ! @metrics[:calls].has_key?(key)
       @metrics[:calls][key] = 0
       @metrics[:sets][key] = 0
       @metrics[:gets][key] = 0
       @metrics[:deletes][key] = 0
       @metrics[:hits][key] = 0
       @metrics[:objsize][key] = 0
    end
  end

  def start
    cap = Pcap::Capture.open_live(@source, 1500)

    @metrics[:start_time] = Time.new.to_f

    @done    = false

    cap.setfilter("port #{@port}")
    cap.loop do |packet|
      @metrics[:stats] = cap.stats

      # hit on a get parse key name, and size from VALUE responses
      if packet.raw_data =~ /STAT /
        next
      end
		
      # hit on a get parse key name, and size from VALUE responses
      if packet.raw_data =~ /VALUE (\S+) \S+ (\S+)/
      key   = $1
      bytes = $2
      @semaphore.synchronize do
        self.command(key)
        @metrics[:hits][key] += 1
        @metrics[:objsize][key] = bytes.to_i
        end
      end

      # parse key name
      # gets ?    
      if packet.raw_data =~ /get (\S+)\r\n/
        key   = $1
        @semaphore.synchronize do
          self.command(key)
          @metrics[:gets][key] += 1
          @metrics[:calls][key] += 1
        end
      end


      # parse key/ name and size
      if packet.raw_data =~ /set (\S+) (\S+) (\S+) (\S+)\r\n/
        key   = $1
        bytes = $4;
        @semaphore.synchronize do
          self.command(key)
          @metrics[:sets][key] += 1
          # @log.warn(packet.raw_data)
          @metrics[:calls][key] += 1
          @metrics[:objsize][key] = bytes.to_i;
        end
      end


      # parse key name
      # delete     
      if packet.raw_data =~ /delete (\S+)/
        key   = $1
        @semaphore.synchronize do
          self.command(key)
            @metrics[:deletes][key] += 1
            @metrics[:calls][key] += 1
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
