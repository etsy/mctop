require 'curses'

include Curses

class UI
    def initialize(config)
	@config = config

        init_screen
        cbreak
        curs_set(0)

        # set keyboard input timeout - sneaky way to manage refresh rate
        Curses.timeout = @config[:refresh_rate]

        if can_change_color?
            start_color
            init_pair(0, COLOR_WHITE, COLOR_BLACK)
            init_pair(1, COLOR_WHITE, COLOR_BLUE)
            init_pair(2, COLOR_WHITE, COLOR_RED)
        end

        @stat_cols      = %w[ calls server client objsize req/sec bw(kbps) ]
        @stat_col_width = 10
        @key_col_width  = 0

        @commands = {
            'Q' => "quit",
            'C' => "sort by calls",
            'E' => "sort by server calls",
            'L' => "sort by client calls",
            'S' => "sort by size",
            'R' => "sort by req/sec",
            'B' => "sort by bandwidth",
            'T' => "toggle sort order (asc|desc)"
        }
    end

    def header
        # pad stat columns to @stat_col_width
        @stat_cols = @stat_cols.map { |c| sprintf("%#{@stat_col_width}s", c) }

        # key column width is whatever is left over
        @key_col_width = cols - (@stat_cols.length * @stat_col_width)

        attrset(color_pair(1))
        setpos(0,0)
        addstr(sprintf "%-#{@key_col_width}s%s", "memcache key", @stat_cols.join)
    end

    def footer
        footer_text = @commands.map { |k,v| "#{k}:#{v}" }.join(' | ')
        setpos(lines-1, 0)
        attrset(color_pair(2))
        addstr(sprintf "%-#{cols}s", footer_text)
    end

    def render_stats(sniffer, sort_mode, sort_order = :desc)
        render_start_t = Time.now.to_f * 1000

        # subtract header + footer lines
        maxlines = lines - 3
        offset   = 1

        # calculate packet loss ratio
        if sniffer.metrics[:stats][:recv] > 0
            loss = sprintf("%5.2f", (sniffer.metrics[:stats][:drop].to_f / sniffer.metrics[:stats][:recv].to_f) * 100)
        else
            loss = 0
        end

        # construct and render footer stats line
        setpos(lines-2,0)
        attrset(color_pair(2))
        header_summary = sprintf "%-28s %-14s %-30s", 
            "sort mode: #{sort_mode.to_s} (#{sort_order.to_s})",
            "keys: #{sniffer.metrics[:calls].keys.count}",
            "packets (recv/dropped): #{sniffer.metrics[:stats][:recv]} / #{sniffer.metrics[:stats][:drop]} (#{loss}%)" 
        addstr(sprintf "%-#{cols}s", header_summary)

        # reset colours for main key display
        attrset(color_pair(0))

        top = []

        sniffer.semaphore.synchronize do 
            # we may have seen no packets received on the sniffer thread 
            return if sniffer.metrics[:start_time].nil?

            elapsed = Time.now.to_f - sniffer.metrics[:start_time]

            # iterate over all the keys in the metrics hash and calculate some values
            sniffer.metrics[:calls].each do |k,v|
                    reqsec = v / elapsed

                    # if req/sec is <= the discard threshold delete those keys from
                    # the metrics hash - this is a hack to manage the size of the
                    # metrics hash in high volume environments
                    if reqsec <= @config[:discard_thresh]
                        sniffer.metrics[:calls].delete(k)
                        sniffer.metrics[:objsize].delete(k)
                        sniffer.metrics[:reqsec].delete(k)
                        sniffer.metrics[:bw].delete(k)
                    else
                        sniffer.metrics[:reqsec][k]  = v / elapsed
                        sniffer.metrics[:bw][k]      = ((sniffer.metrics[:objsize][k] * sniffer.metrics[:reqsec][k]) * 8) / 1000
                    end
            end

            top = sniffer.metrics[sort_mode].sort { |a,b| a[1] <=> b[1] }
        end

        unless sort_order == :asc
            top.reverse!
        end

        for i in 0..maxlines-1
            if i < top.length
                k = top[i][0]
                v = top[i][1]

                # if the key is too wide for the column truncate it and add an ellipsis
                if k.length > @key_col_width
                    display_key = k[0..@key_col_width-4]
                    display_key = "#{display_key}..."
                else
                    display_key = k
                end

                if sniffer.metrics[:server_calls][k].nil?
                  sniffer.metrics[:server_calls][k] = 0
                end

                if sniffer.metrics[:client_calls][k].nil?
                  sniffer.metrics[:client_calls][k] = 0
                end
           
                # render each key
                line = sprintf "%-#{@key_col_width}s %9.d %9.d %9.d %9.d %9.2f %9.2f",
                                 display_key,
                                 sniffer.metrics[:calls][k],
                                 sniffer.metrics[:server_calls][k],
                                 sniffer.metrics[:client_calls][k],
                                 sniffer.metrics[:objsize][k],
                                 sniffer.metrics[:reqsec][k],
                                 sniffer.metrics[:bw][k]
            else
                # we're not clearing the display between renders so erase past
                # keys with blank lines if there's < maxlines of results
                line = " "*cols
            end

            setpos(1+i, 0)
            addstr(line)
        end

        # print render time in status bar
        runtime = (Time.now.to_f * 1000) - render_start_t
        attrset(color_pair(2))
        setpos(lines-2, cols-18)
        addstr(sprintf "rt: %8.3f (ms)", runtime)
    end

    def input_handler
        # Curses.getch has a bug in 1.8.x causing non-blocking
        # calls to block reimplemented using IO.select
        if RUBY_VERSION =~ /^1.8/
	     refresh_secs = @config[:refresh_rate].to_f / 1000 

            if IO.select([STDIN], nil, nil, refresh_secs)
                c = getch
                c.chr
            else
                nil
            end
        else
            getch
        end
    end

    def done
        nocbreak
        close_screen
    end
end
