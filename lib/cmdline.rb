require 'optparse'
require 'pcap'
require 'socket'

class CmdLine
    def self.parse(args)
        @config = {}

        opts = OptionParser.new do |opt|
            opt.on('-i', '--interface=NIC', 'Network interface to sniff (required)') do |nic|
                @config[:nic] = nic
            end

            @config[:port] = 11211
            opt.on('-p', '--port=PORT', 'Network port to sniff on (default 11211)') do |port|
                @config[:port] = port
            end

            @config[:discard_thresh] = 0
            opt.on('-d', '--discard=THRESH', Float, 'Discard keys with request/sec rate below THRESH') do |discard_thresh|
                @config[:discard_thresh] = discard_thresh
            end

            @config[:refresh_rate] = 500
            opt.on('-r', '--refresh=MS', Float, 'Refresh the stats display every MS milliseconds') do |refresh_rate|
                @config[:refresh_rate] = refresh_rate
            end

            @config[:detailed_calls] = false
            opt.on('-c', '--detailed-calls', 'Detailed client/server call stats') do |detailed_calls|
                @config[:detailed_calls] = true
            end

            @config[:ip_address] = IPSocket.getaddress(Socket.gethostname)
            opt.on('-a', '--ip-address=1.1.1.1', 'IP address of memcached instance (used for client/server stats)') do |ip_address|
                @config[:ip_address] = ip_address
            end

            opt.on_tail '-h', '--help', 'Show usage info' do
                puts opts
                exit
            end
        end

        opts.parse!

        # bail if we're not root
        unless Process::Sys.getuid == 0
            puts "** ERROR: needs to run as root to capture packets"
            exit 1
        end

        # we need need a nic to listen on
        unless @config.has_key?(:nic)
            puts "** ERROR: You must specify a network interface to listen on"
            puts opts
            exit 1
        end

        # we can't do 'any' interface just yet due to weirdness with ruby pcap libs
        if @config[:nic] =~ /any/i
            puts "** ERROR: can't bind to any interface due to odd issues with ruby-pcap"
            puts opts
            exit 1
        end

        @config
    end
end
