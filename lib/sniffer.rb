require 'pcap'
require 'thread'

class MemcacheSniffer
    attr_accessor :metrics, :semaphore

    def initialize(config)
        @source         = config[:nic]
        @port           = config[:port]
        @detailed_calls = config[:detailed_calls]
        @ip             = config[:ip_address]


        @metrics = {}
        @metrics[:calls]          = {}
        @metrics[:client_calls]   = {}
        @metrics[:server_calls]   = {}
        @metrics[:objsize]        = {}
        @metrics[:reqsec]         = {}
        @metrics[:bw]             = {}
        @metrics[:stats]          = { :recv => 0, :drop => 0 }

        @semaphore = Mutex.new
    end

    def start
        cap = Pcap::Capture.open_live(@source, 1500)

        @metrics[:start_time] = Time.new.to_f

        @done      = false

        cap.setfilter("port #{@port}")
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

                  if @detailed_calls
                      # Break down keys by server requests and client requests
                      if @ip == packet.src.to_s
                          if @metrics[:server_calls].has_key?(key)
                              @metrics[:server_calls][key] += 1
                          else
                              @metrics[:server_calls][key] = 1
                          end
                      end

                      if @ip == packet.dst.to_s
                          if @metrics[:client_calls].has_key?(key)
                              @metrics[:client_calls][key] += 1
                          else
                              @metrics[:client_calls][key] = 1
                          end
                      end
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
