require 'pcap'
require 'thread'


class MemcacheSniffer
    attr_accessor :metrics, :semaphore

    def initialize(config)
        @source    = config[:nic]
        @port      = config[:port]

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
    end

    def start
        cap = Pcap::Capture.open_live(@source, 1500)

        @metrics[:start_time] = Time.new.to_f

        @done      = false

        cap.setfilter("port #{@port}")
        cap.loop do |packet|
            @metrics[:stats] = cap.stats
		
            # hit on a get parse key name, and size from VALUE responses
            if packet.raw_data =~ /VALUE (\S+) \S+ (\S+)/
                key   = $1
                bytes = $2

                @semaphore.synchronize do
                    if @metrics[:hits].has_key?(key)
                        @metrics[:hits][key] += 1
                    else
                        @metrics[:hits][key] = 1
                    end

                    @metrics[:objsize][key] = bytes.to_i
                end
            end

	# parse key name
        # gets ?    
            if packet.raw_data =~ /get (\S+)/
                key   = $1
                @semaphore.synchronize do
                    if @metrics[:calls].has_key?(key)
                        @metrics[:calls][key] += 1
                    else
                        @metrics[:calls][key] = 1
                    end
		    @metrics[:objsize][key] = 0;
                    if @metrics[:gets].has_key?(key)
                        @metrics[:gets][key] += 1
                    else
                        @metrics[:gets][key] = 1
                    end
                end
            end


	   # parse key name and size
            if packet.raw_data =~ /set (\S+) (\S+) (\S+) (\S+)/
                key   = $1
		bytes = $4;
                @semaphore.synchronize do
                    if @metrics[:calls].has_key?(key)
                        @metrics[:calls][key] += 1
                    else
                        @metrics[:calls][key] = 1
                    end
                    if @metrics[:sets].has_key?(key)
                        @metrics[:sets][key] += 1
                    else
                        @metrics[:sets][key] = 1
                    end
                    @metrics[:objsize][key] = $bytes.to_i;
                end
            end


        # parse key name
        # delete     
            if packet.raw_data =~ /delete (\S+)/
                key   = $1
                @semaphore.synchronize do
                    if @metrics[:calls].has_key?(key)
                        @metrics[:calls][key] += 1
                    else
                        @metrics[:calls][key] = 1
                    end
                    @metrics[:objsize][key] = 0;
                    if @metrics[:deletes].has_key?(key)
                        @metrics[:deletes][key] += 1
                    else
                        @metrics[:deletes][key] = 1
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
