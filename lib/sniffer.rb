require 'pcap'
require 'thread'

class MemcacheSniffer 
    attr_accessor :metrics, :semaphore

    def initialize(config)
        @source    = config[:nic]

        @metrics = {}
        @metrics[:calls]   = {}
        @metrics[:objsize] = {}
        @metrics[:reqsec]  = {}
        @metrics[:bw]      = {}
        @metrics[:stats]   = { :recv => 0, :drop => 0 }

        @semaphore = Mutex.new
    end

    def start
        cap = Pcap::Capture.open_live(@source, 1500)
        
        @metrics[:start_time] = Time.new.to_f

        @done      = false

        cap.setfilter('port 11211')
        cap.loop do |packet|
            @metrics[:stats] = cap.stats

            # parse key name, and size from VALUE responses
            if packet.raw_data =~ /VALUE (\S+) \S+ (\S+)/
                key   = $1
                bytes = $2

                @semaphore.synchronize do
                    if @metrics[:calls].has_key?(key)
                        @metrics[:calls][key] += 1
                    else
                        @metrics[:calls][key] = 1
                    end

                    @metrics[:objsize][key] = bytes.to_i
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
