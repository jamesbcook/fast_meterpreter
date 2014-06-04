#!/usr/bin/env ruby
require_relative 'core'
module Menu
  def webhost_alert
    puts '*' * 50
    puts 'Setting up webserver to host the powershell script'
    puts '*' * 50
  end

  def msfhost_alert
    puts '*' * 30
    puts 'Setting up the MSF server'
    puts '*' * 30
  end
end
