					Maverick 0.9 README
						
				

What's this program for? 
"maverick.pl" is designed to be a security consultant's quick parser. As of version 0.9, 
 	a) It can perform IP blocks whois audit against client's domain in batch. 
 	b) It can perform network AS number lookup by querying 'whois.cymru.com' in batch.
 	c) It can dump and filter out found open ports only from the Nmap result file (xml format only).
 	d) It can parse Nessus findings grouped by plugin ID and sorted by severity descendingly.
	e) It can dump out Nessus scan timestamp table.
	f) It can dump out plugin output table line by line for a specific Nessus Plugin ID.
	g) It can dump out public exploitable findings only from Nessus (Nessus v2 format only).
	h) It can dump out weak cipher table from Nessus.
	i) It can dump out web server type table from Nessus.
	j) It can dump out web engine software 'X-Powered-By' table from Nessus .
	k) It can call Nikto to audit all found web servers from Nessus in one command.


Why is this program? 
It's a tool to speed up a typical security assessment assignment, and reduce human error rate on repeating mundanes.


How about the running environment requirement?
Technically the code could be run in any system that have Perl interpreter and internet access. As Perl is a standard
package in most computer today, your chance is pretty high. You may need to install certain extended Perl modules from
Internet as shown below, as most of them are not 'bundled'. For Windows user, you could install Cygwin or ActivePerl. 
The codes are produced and tested under Debian / Windows Cygwin environment.


How do I set up the Perl environment for this program?
a) You need a PERL environment. Traditionally it means a Unix/Linux box. You can also use Cygwin in Windows box.
Before using the program, please make sure you have PERL version 5.8 and above available. You may also need 
to download and install the following modules from CPAN.org:
	XML::LibXML;
	Net::CIDR;
	Net::Whois::ARIN;
	Nmap::Parser;
	Switch;
	Spreadsheet::WriteExcel;
	Spreadsheet::ParseExcel;
	Spreadsheet::ParseExcel::SaveParser;			
	Data::Dumper;
	Encode;
To install the above modules, you may need the 'root' or 'administrator' privilege in the box. You could follow the 
package instructions to manually install them one by one. It could be a long process as the modules may have dependencies  
requirement. I found it's faster to start with CPAN.pm installer method below whenever I can:
	# perl -MCPAN -eshell
	eshell> install Net::CIDR
	... 		<- just press 'Enter' for default if prompted.
	eshell> install Net::Whois::ARIN
	...
	eshell> exit
b) Now unzip and set the executable bit of this program.
	$ unzip Maverick.zip
	$ cd Maverick
	$ chmod +x maverick.pl
	$ ./maverick.pl -help 


What if I don't bother to setup the Perl environment? 
The program is now packaged into a 'standalone' format in this distribution.  So you can save the trouble to compile many dependant 
modules used by this program. The 'builds' are done under Debain and Cygwin environment by Perl PAR packer. For example, 'maverick.linux' is built 
from my Debian 5.0.3 VM, and 'maverick.exe' is built from 'CYGWIN_NT-6.1-WOW64' under my Dell E6500 laptop. You may be able to run them 
in the similar environment of yours, without setting up a full working Perl environment. 


Do you have usage examples?
Usage Examples:
	Example 1, to perform IP blocks whois audit against client's domain:
          $ maverick -a audit_ips -i '98.124.174.0/24,69.147.64.0/18,76.13.0.0/16,155.71.3.245' -d 'www.yahoo.com'
	Example 2, to perform network AS number lookup on a list of IP blocks:
	  $ maverick -a aslookup -i '98.124.174.0/24,69.147.64.0/18,76.13.0.0/16'
	Example 3, to dump and filter out open ports only from Nmap result file (xml format only):
	  $ maverick -a nmapxml -f target_nmap.xml
	Example 4, to parse Nessus findings grouped by Plugin ID and sorted by severity descendingly:
	  $ maverick -a nbe -f target.nbe | less
	  $ maverick -a nessus -f target.nessus -o report.txt
	Example 5, to dump out Nessus scan timestamp table:
	  $ maverick -a timestamp -f target.nbe | less
	Example 6, to dump out plugin output table line by line for a specific Nessus Plugin ID 10107:
	  $ maverick -a pluginoutput -f target.nbe -g  10107 -o pout.txt
	Example 7, to print out public exploitable Nessus findings only:
	  $ maverick -a exploitable -f target.nessus -o exploitable.txt
	Example 8, to dump out weak ciphers table from Nessus (BT EHCOE report requirement):
	  $ maverick -a weakcipher -f target.nbe
	Example 9, to dump out web server type table from Nessus (BT EHCOE report requirement):
	  $ maverick -a webtype -f target.nbe
	Example 10, to dump out web engine software (X-Powered-By header) table from Nessus (BT EHCOE report requirement):
	  $ maverick -a websoftware -f target.nbe
	Example 11, to call Nikto audit on all found web servers by Nessus (BT EHCOE report requirement):
	  $ maverick -a exec_nikto -f target.nbe



How do I report the bugs, or maybe require some new features? 
Contact the author Yang Li directly at email 'Yang.Li@usc-bt.com' or phone (917) 667.1972



Legal Disclaimer: 
This software is provided strictly 'as-if' without any implied warranty. You're free to copy or modify the codes anyway you want - a reference back to this software will be appreciated. 
Other than the software itself, Perl and the modules used in this software fall under GPL license - http://dev.perl.org/licenses/gpl1.html. 
