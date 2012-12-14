# mctop


Inspired by "top", mctop passively sniffs the network traffic passing in and out of a
server's network interface and tracks the keys responding to memcache get commands. The output
is presented on the terminal and allows sorting by total calls, requests/sec and
bandwidth.

You can read more detail about why this tool evolved over on our
[code as craft](http://codeascraft.etsy.com/2012/12/13/mctop-a-tool-for-analyzing-memcache-get-traffic) blog.

mctop depends on the [ruby-pcap](https://rubygems.org/gems/ruby-pcap) gem, if you don't have 
this installed you'll need to ensure you have the development pcap libraries (libpcap-devel 
package on most linux distros) to build the native gem.

![](http://etsycodeascraft.files.wordpress.com/2012/12/mctop.jpg)

## How it works

mctop sniffs network traffic collecting memcache `VALUE` responses and calculates
traffic statistics for each key seen.  It currently reports on the following metrics per key:

* **calls** - the number of times the key has been called since mctop started 
* **objsize** - the size of the object stored for that key
* **req/sec** - the number of requests per second for the key
* **bw (kbps)** - the estimated network bandwidth consumed by this key in kilobits-per-second

## Getting it running

the quickest way to get it running is to:

* ensure you have libpcap-devel installed
* git clone this repo
* in the top level directory of this repo `bundle install` (this will install the deps)
* then either:
    * install it locally `rake install`; or
    * run it from the repo (good for hacking) `sudo ./bin/mctop --help`

## Command line options

    Usage: mctop [options]
        -i, --interface=NIC              Network interface to sniff (required)
        -d, --discard=THRESH             Discard keys with request/sec rate below THRESH
        -r, --refresh=MS                 Refresh the stats display every MS milliseconds
        -h, --help                       Show usage info

## User interface commands

The following key commands are available in the console UI:

* `C` - sort by number of calls
* `S` - sort by object size
* `R` - sort by requests/sec
* `B` - sort by bandwidth
* `T` - toggle sorting by ascending / descending order
* `Q` - quits

## Status bar

The following details are displayed in the status bar

* `sort mode` - the current sort mode and ordering
* `keys` - total number of keys in the metrics table
* `packets` - packets received and dropped by libpcap (% is percentage of packets dropped)
* `rt` - the time taken to sort and render the stats

## Known issues / Gotchas

### ruby-pcap drops packets at high volume
From my testing the ruby-pcap native interface to libpcap struggles to keep up with high packet rates (in what we see on a production memcache instance). 
You can keep an eye on the packets recv/drop and loss percentage on the status bar at the bottom of the UI to get an idea of the packet loss on your machine.

