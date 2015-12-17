
def error(msg = 'SystemTap (dtrace) support was not detected.')
  puts "ERROR: #{msg}."
  exit false
end

probes_d = 'probes.d'
libruby_so = 'libruby.so.2.3'

error unless `readelf -S "#{libruby_so}"`.lines.detect do |x|
  x.lstrip!
  x[0] == '[' && x =~ / \.stapsdt\.base /

end

missing = ['insn', 'insn__operand']

probes = []

File.open(probes_d) do |file|
  file.each_line do |line|
    line.lstrip!
    probes << line.split[1].split('(')[0] if line =~ /^probe \S+\(/
  end
end

probes = probes.uniq.sort

error "Missing probes in file '#{probes_d}'" unless (missing - probes).empty?

regex = /\n  stapsdt              0x\S+\tNT_STAPSDT \(SystemTap probe descriptors\)\n    Provider: ruby\n    Name: (\S+)\n/

taps = `readelf -n "#{libruby_so}"`.scan(regex).flatten.uniq

probes -= taps

error unless probes.eql?(missing)

exit true
