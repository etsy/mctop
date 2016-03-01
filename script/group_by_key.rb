#!/usr/bin/ruby

require 'csv'
require 'curses'

include Curses
include Curses::Key

def input_handler
  # Curses.getch has a bug in 1.8.x causing non-blocking
  # calls to block reimplemented using IO.select
  if RUBY_VERSION =~ /^1.8/
   refresh_secs = 500.to_f / 1000

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

init_screen
cbreak
curs_set(0)
Curses.timeout = 500

if can_change_color?
  start_color
  init_pair(0, COLOR_WHITE, COLOR_BLACK)
  init_pair(1, COLOR_WHITE, COLOR_BLUE)
  init_pair(2, COLOR_WHITE, COLOR_RED)
  init_pair(3, COLOR_WHITE|A_BOLD, COLOR_CYAN)
end

commands = {
  'Q' => "quit",
  'J' => "join",
  "S" => "split",
  "P" => "prev",
  "N" => "next",
  "D" => "dump"
}

# load stats
dump = "dump.csv"
metrics = {}
metrics[:raw] = {}
metrics[:raw][:calls] = {}
metrics[:raw][:keys] = {}
metrics[:raw][:bw] = {}
CSV.open(dump, 'r') do |row|
  metrics[:raw][:calls][row[0].to_s] = row[1].to_i
  metrics[:raw][:keys][row[0].to_s] = 1
  metrics[:raw][:bw][row[0].to_s] = (row[1].to_i) * (row[2].to_i)
end
keys = metrics[:raw][:calls].keys.sort
prefix = []
update = true

done = false
dump = false
offset = 0
posy = 0

until done do

  # compute aggregate
  if update
    top = []
    metrics[:agg] = {}
    metrics[:agg][:calls] = {}
    metrics[:agg][:keys] = {}
    metrics[:agg][:bw] = {}
    keys.each do |k|
      t = :raw
      prefix.each do |p|
        if k[0,p.length] == p
          t = :agg
          if metrics[t][:calls].has_key?(p)
            metrics[t][:calls][p] += metrics[:raw][:calls][k]
            metrics[t][:keys][p] += 1
            metrics[t][:bw][p] += metrics[:raw][:bw][k]
          else
            top << [p,t]
            metrics[t][:calls][p] = metrics[:raw][:calls][k]
            metrics[t][:keys][p] = 1
            metrics[t][:bw][p] = metrics[:raw][:bw][k]
          end
          break
        end
      end
      if t == :raw
        top << [k,t]
      end
    end
    update = false
  end

  # render header
  stat_cols = %w[ calls objsize keys size(kb) ]
  stat_col_width = 10
  stat_cols = stat_cols.map { |c| sprintf("%#{stat_col_width}s", c) }
  key_col_width = cols - (stat_cols.length * stat_col_width)
  attrset(color_pair(1))
  setpos(0,0)
  addstr(sprintf "%-#{key_col_width}s%s", "memcache key", stat_cols.join)

  # render stats
  maxlines = lines - 2
  for i in 0..maxlines-1
    if i == posy
      attrset(color_pair(3))
    else
      attrset(color_pair(0))
    end
    if i < offset + top.length
      k,t = top[i + offset]
      if k.length > key_col_width
        display_key = k[0..key_col_width-4]
        display_key = "#{display_key}..."
      else
        display_key = k
      end
      calls = metrics[t][:calls][k]
      dkeys = metrics[t][:keys][k]
      size = metrics[t][:bw][k].to_f / 1024
      if calls > 0
        objsize = 1024 * size / calls
      else
        objsize = 0
      end
      line = sprintf "%-#{key_col_width}s %9.d %9.2f %9.d %9.2f",
        display_key, calls, objsize, dkeys, size
    else
      line = " " * cols
    end
    setpos(1+i, 0)
    addstr(line)
  end

  # render footer
  footer_text = commands.map { |k,v| "#{k}:#{v}" }.join(' | ')
  setpos(lines-1, 0)
  attrset(color_pair(2))
  addstr(sprintf "%-#{cols}s", footer_text)

  refresh

  case input_handler
    when /[Qq]/
      done = true
    when /[Pp]/
      if posy > 0
        posy -= 1
      else
        if offset > 0
          offset -= 1
        end
      end
    when /[Nn]/
      if posy < maxlines-1 and posy + offset < top.length-1
        posy += 1
      else
        if offset < top.length-maxlines
          offset +=1
        end
      end
    when /[Jj]/
      if offset + posy < top.length-2
        p = ""
        k = top[offset + posy][0]
        n = top[offset + posy + 1][0]
        for i in 0..k.length-1
          if i < n.length-1
            if k[i] == n[i]
              p << k[i]
            else
              break
            end
          else
            break
          end
        end
        if p.length > 0
          prefix << p
          prefix = prefix.sort
          update = true
        end
      end
    when /[Ss]/
      if top[offset + posy][1] == :agg
        prefix.delete(top[offset + posy][0])
        prefix = prefix.sort
        update = true
      end
    when /[Dd]/
      done = true
      dump = true
  end
end

nocbreak
close_screen

if dump
  puts "Dumping stats.."
  CSV.open("stat.csv", "w") do |csv|
    top.each do |k,t|
      calls = metrics[t][:calls][k]
      dkeys = metrics[t][:keys][k]
      size = metrics[t][:bw][k].to_f / 1024
      if calls > 0
        objsize = 1024 * size / calls
      else
        objsize = 0
      end
      csv << [k, calls, objsize, dkeys, size]
    end
  end
end
