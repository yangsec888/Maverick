#!/usr/bin/perl
########################################################################
# Functional Description: 
#                                                                  
# maverick.pl is designed to be a security consultant's quick parser. 
# For more detail, check out the REAME.txt or run the following command:
# 	$ maverick.pl -h
# 
########################################################################
# Designed and developed by:		Yang Li
#
# Change History: 
# Last modification: 	11/09/2011
#	Version		0.9h
#	
#	11/21/2011	Refactor and add weak cipher table into Easy Reporting feature.
#	11/09/2011	Redefine "-o " switch for the Easy Reporting feature so the program could be more flexible.
#	10/26/2011	Restructure %BTFINDS data structure, in order to support the merging of multiple Nessus findings into one BT finding.
#	10/25/2011	Some format changes/enhancements for the HTML report.
#	10/21/2011	Add support to better sorting of findings in BT EHCOH baseline report by using BT risk level instead of Nessus'.	
#	10/18/2011	Refactor the code and some minor bug fixes.
#	10/12/2011	Start working on supporting of EHCOE xml repository for Maverick's Easy Reporting feature.
#	07/09/2011	Bug fix of missing NULL ciphers in 'search_weak_cipher' function.
#	03/25/2011	Optimize %FINDINGS data structure. Using array instead of list for 3 elements that would further optimize parsing speed. 
#	03/24/2011	Bug fix on '-a timestamp' switch when parsing 'nbe' file.
#	03/22/2011	User CLI interface change, merge of '-a nbe' command switch to '-a nessus'. 
#	03/21/2011	Implement the Nessus v1 format parser. 
#	03/19/2011	Replace XML parser from XML::DOM to XML::LibXML; minor bug fixes.  
#	03/18/2011	Implement the action switch '-a exploitable' to narrow down "exploitable" findings (Nessus v2 only); 
#			Bug fix on '-a exec_nikto'; New field support 'Nessus Plugin ID' in the mapping report 'report.xls'.
#	03/15/2011	Misc bug fixes: Nessus v2 parser; 'extract_osvdb_from_nessus' function; compatible of Nessusv2 for the rest 
#			of the program.
#	03/13/2011	Implement the Nessus v2 format parser; 'search_weak_cipher' function bug fix 
#	03/10/2011	Reimplement search algorithm for auto-reporting feature, to maximize the search performance
#	03/08/2011	Implement the '-a timestamp' command switch to print out Nessus timestamp table; 
#			revise 'search_pid_xls_repository' function
#	03/07/2011	Implement the '-a pluginoutput' command switch.
#	03/07/2011	Refactor 'parse_nbe' and other codes to make it more flexible; preparing for compatibility of 
#			Nessus v1, v2 format parsing
#	03/06/2011	Implement the action switch '-a websoftware'
#	03/03/2011	Implement the optional '-output' command switch throughout the program, as per Renato's suggestion
#	03/01/2011	Implement verbose mode for Maverick; add filter_input_action function for security sanity check
#	03/01/2011	Remove Nikto hardcoded path, add Nikto auto-search function
#	12/01/2010	Support calling Nikto audit on all found http(s) servers found by Nessus
#	12/01/2010	Implement Nessus "Evidences" field in the baseline report
#	11/29/2010	Support web server type table dumping out from nbe as per Renato's suggestion
#	11/23/2010	Support weak ciphers table dumping out from nbe
#	09/23/2010	Bug fix on 'extract_cve_from_nessus' function
#	08/05/2010	Bug fixes on PID matching etc.. And more restrict input validations per Renato's suggestion
#	07/25/2010	Support Nessus nbe to BT template auto-mapping
#	12/15/2009	Support Nessus nbe report finding organized by plugin id and sorted by severity descendingly 
#	11/22/2009	Support Nmap XML result quick parsing 
#	11/06/2009	Support network AS number lookup as per Jason's suggestion
#	11/04/2009	Various bugs fixed, support IP blocks whois audit
#	11/03/2009	Program basic I/O defined & functions developed 
########################################################################	 
# Load extended Perl modules/libraries
use Getopt::Long qw/:config bundling_override no_ignore_case/;
use XML::LibXML;
use HTML::Entities;
use Switch;
use Net::CIDR;
use Net::Whois::ARIN;
use Nmap::Parser;
use Spreadsheet::WriteExcel;
use Spreadsheet::ParseExcel;
use Spreadsheet::ParseExcel::SaveParser;			
use Data::Dumper;
use Encode;
########################################################################
## Program Argument Check
########################################################################
my $ver="0.9h", $author="Yang Li";				# Program Version and Author
my $verbose;							# Verbose mode for Maverick
my %opts;
GetOptions(
	\%opts,
	'help|h|?' => sub { &print_help and exit 0; },		# Print help
	'version|v:s' => sub { &print_banner; exit 0;},		# Print program version information
	'action|a:s',						# Program action options. See README.txt or examples below for details. 
	'ips|i:s',						# IP list - i.e. IP blocks in comma seperated format. 
								# For example: '98.124.174.0/24,69.147.64.0/18,76.13.0.0/16,155.71.3.245'  
	'domain|d:s',						# Client's domain. For example: 'yahoo.com'
	'file|f:s',                  	 			# Program input file (.xml, .nbe, .nessus)
	'output|o:s',               				# Optional, program output result file 
	'mapping|m:s',						# Optional, map Nessus scan file to BT EHCOE repositories for Easy Reporting
	'path|p:s',                                     	# Optional, for example to define absolute executable path to Nikto as '-p /usr/local/nikto/'
	'pid|g:s',						# Nessus plugin ID for detail plugin-output analysis
	'verbose+' => \$verbose,				# Optional, program verbose mode for debugging
	'vv+' => \$verbose,					# Same as "-verbose", abbreviation "-vv"
);				
my $mapping = defined $opts{mapping} ? 
		$opts{mapping} : 'mapping.conf';		# default mapping configuration file
########################################################################
# Main Program
########################################################################
our @NETBLKS;							# Global array contains found netblocks belonged to the client's domain
our %AS;							# Global hash contains found AS number table 
our %FINDINGS;							# Global hash contains Nessus findings table
our %BTFINDINGS;						# Global hash contains BT baseline report finding index with BT risk level tracking
our %TIMESTAMPS;						# Global hash contains Nessus scan timestamps
our %CNF;							# Global hash contains Nessus to BT EHCOE finding template repository mapping configuration 
our @ENTRS;							# Global array contains indexes of BT EHCOE xls finding repository 
our %DBVIDS;							# Global hash contains indexes of BT EHCOE xls finding repository 
our %DBXML;							# Global hash contains indexes of BT EHCOE xml finding repository
our %WC;							# Global hash to store weak cipher table
unless( $opts{ips} or $opts{file} )  {				# Program input quick sanity check
	&print_help and exit(1); 
} 
if ( filter_input_action ($opts{action}) ) {			# Program action sanity check
	&print_banner;
	&filter_input_file;					# Program input file extension quick sanity check
	switch ($opts{action}) {
		case "aslookup"	{ lookup_as_number (); } 	# Perform AS number lookup for list of IP blocks
		case "nmapxml"	{ parse_nmap_terse (); } 	# Parse NMAP result in XML and dump out open ports only
		case "nessus"	{ 				# Parse Nessus result in Nessus format then generate the sorted report
			parse_nessus();			
			print_nessus_report();
		} 
		case "timestamp" { print_nessus_timestamps();}	# Dump out Nessus scan timestamps report	
		case "weakcipher" { 				# Dump out weak cipher table from Nessus file
			parse_nessus();			
			dump_weak_ciphers ();
			print_weak_cipher_table ();
		}	
		case "webtype"	{ dump_web_svr_type ();}	# Dump out web server type table from Nessus file
		case "websoftware" { dump_web_software ();}	# Dump out web engine software table from Nessus file
		case "exec_nikto" { exec_nikto ();	}	# Perform nikto audit on every found http(s) server
		case "audit_ips"{ audit_ip_blocks ();  }     	# Perform IP network blocks audit against client's domain  
		case "pluginoutput" { dump_plugin_output (); }	# Dump out plugin output detail from Nessus file
		case "exploitable" {				# Parse Nessusv2 result then print out sorted exploitable findings in the report
			print_exploitable_report(); 
		}	
		else { 						# Error handler
			die "Program action unknown: $opts{action}\n";
		}     	
	}
}
exit (0);

########################################################################
# Functions & Subroutines
########################################################################
sub print_help () {
  #
  # print help for user
  #
        my $ph = (split /[\\|\/]/, $0)[-1];
        &print_banner;
	print <<HELP;
Functional Description:
maverick.pl is designed to be a security consultant's quick parser. It's most useful if you have a large scale assignment. Since manual procedures would be a time-consuming alternative.
 	a) It can perform IP blocks whois audit against client's domain in batch. 
 	b) It can perform network AS number lookup by querying 'whois.cymru.com' in batch.
 	c) It can dump and filter out found open ports only from the Nmap result file (xml format only).
 	d) It can parse Nessus findings grouped by plugin ID and sorted by severity descendingly.
	e) It can dump out Nessus scan timestamp table.
	f) It can dump out plugin output table line by line for a specific Nessus Plugin ID.
	g) It can dump out public exploitable findings only from Nessus (Nessus v2 format only).
	h) It can dump out weak cipher table from Nessus (BT EHCOE report requirement).
	i) It can dump out web server type table from Nessus (BT EHCOE report requirement).
	j) It can dump out web engine software 'X-Powered-By' table from Nessus (BT EHCOE report requirement).
	k) It can call Nikto to audit all found web servers from Nessus in one command (BT EHCOE report requirement).
	l) It can map Nessus findings to BT EHCOE finding repository (BT EHCOE report requirement).

Syntax:
	\$ $ph ?|-h|--help
			-h|?|help		Print help message
			-a|action		Program action options 
			-f|file			File as program input (xml,nbe,nessus, etc.)
			-o|output		Optional program output file
			-i|ips			Optional, clinet's IP blocks list as program input (comma seperated)
			-d|domain		Optional, client's domain for batch whois audit
			-m|mapping		Optional Easy Reporting feature -  map Nessus findings to BT EHCOE repository 
			-p|path			Optional, to define additional path for Nikto such as '-p /usr/local/nikto/'
			-g|pid			Optional, Nessus plugin ID for plugin-output table
			-vv|verbose		Program in verbose mode
			-v|version		Program version	

Usage Examples:
	Example 1, to perform IP blocks whois audit against client's domain:
	\t\$ $ph -a audit_ips -i '98.124.174.0/24,69.147.64.0/18,76.13.0.0/16' -d 'www.yahoo.com'
	Example 2, to perform network AS number lookup on a list of IP blocks:
	\t\$ $ph -a aslookup -i '98.124.174.0/24,69.147.64.0/18,76.13.0.0/16'
	Example 3, to dump and filter out open ports only from Nmap result file (xml format only):
	\t\$ $ph -a nmapxml -f target_nmap.xml
	Example 4, to parse Nessus findings grouped by Plugin ID and sorted by severity descendingly:
	\t\$ $ph -a nessus -f target.nbe | less
	\t\$ $ph -a nessus -f target.nessus -o report.txt
	Example 5, to dump out Nessus scan timestamp table:
	\t\$ $ph -a timestamp -f target.nbe | less
	Example 6, to dump out plugin output table line by line for a specific Nessus Plugin ID 10107:
	\t\$ $ph -a pluginoutput -f target.nbe -g  10107 -o pout.txt
	Example 7, to print out public exploitable Nessus findings only:
	\t\$ $ph -a exploitable -f target.nessus -o exploitable.txt
	Example 8, to dump out weak ciphers table from Nessus (BT EHCOE report requirement):
	\t\$ $ph -a weakcipher -f target.nbe
	Example 9, to dump out web server type table from Nessus (BT EHCOE report requirement):
	\t\$ $ph -a webtype -f target.nbe
	Example 10, to dump out web engine software (X-Powered-By header) table from Nessus (BT EHCOE report requirement):
	\t\$ $ph -a websoftware -f target.nbe
	Example 11, to call Nikto audit on all found web servers by Nessus in one command (BT EHCOE report requirement):
	\t\$ $ph -a exec_nikto -f target.nbe
	Example 12, to parse then map Nessus findings to BT EHCOE repository. A BT EHCOE baseline report will be generated by the program:
	\t\$ $ph -a nessus -f target.nbe -m mapping.conf -o unmatched.txt
HELP
}

sub read_config_simple {
#
## Read the program mapping file, store setting into hash %CNF
#
	open (CONFIG, $_[0]) || die "Problem reading program mapping file $config: $! \nPlease read the README.txt again.\n";
	while (my $line=<CONFIG>) {
		chomp($line);
		$line =~ s/\s+//g;
		if ($line =~ /(^#|^\s+#)/) {
			next;
		} elsif ($line =~ /^(.*)=(.*)/) {
			$CNF{$1} = $2;
		} else {
			next;
		}
	}
	close (CONFIG);
}

sub filter_input_action () {
  #
  ## Input filter to watch for the right program action switch "-a" or "-action". If no legitimate action defined by the command switch, 
  ## the program would stop proceeding further. 
  #  
	my $permission=0;
	@action_allowed = ('aslookup', 'nmapxml', 'nessus', 'timestamp', 'audit_ips', 'weakcipher', 'webtype', 'exec_nikto', 'websoftware', 'pluginoutput', 'exploitable');
	foreach (@action_allowed) {
		chomp; s/\s//g;
		if ($_ eq $_[0]) { $permission++; }
	}
	if ($permission) { 
		return 1;
	} else {
		&print_help;
		die "\nError: Program action \'$opts{action}\' is not defined nor allowed.\n";
	}
}

sub filter_input_file () {
  #
  ## Input filter to validate program input file extension.
  #
	my $proceeding=0;
	if ($opts{ips}) { $proceeding++; } 				# Exception for IP block action that use IP list instead
	@file_allowed = ('nbe','xml', 'nessus');			# List of allowed file extensions as the program input
	my @EXT=split(/\./,$opts{file});
	my $ext=$EXT[$#EXT];
	foreach (@file_allowed) {
		chomp;
		s/\s//g;
		if ($_ eq $ext) {
			$proceeding++;	
		}
	}
	unless ($proceeding) { 	
		die "Error! Program input file $opts{file} has un-supported file extension: $ext\n";  
	} else  {
		return $proceeding;
	}
}

sub input_file_is_nbe () {
  #
  ## Determine ".nbe" file extension. So Maverick could choose the right parser
  #
	my @EXT=split(/\./,$opts{file});
	my $ext=$EXT[$#EXT];
	if ($ext eq  "nbe") {
		return 1;
	} else {
		return 0;
	}
}

sub input_file_is_nessus () {
  #
  ## Determine ".nessus" file extension. So Maverick could choose the right parser
  #
	my $found=0;
	my @EXT=split(/\./,$opts{file});
	my $ext=$EXT[$#EXT];	
	if ($ext eq  "nessus") {
		open (CHK,$opts{file}) || die "Can't open Nessus file $opts{file}: $!";
		while (<CHK>) {
			chomp;
			if (/^\<NessusClientData_v2\>/) {
				$found=2;	
				last;
			} elsif (/^\<NessusClientData\>$/) {
				$found=1;
				last;
			} else {
				next;
			}
		}
		close(CHK);
	}
	return $found;
}

sub parse_nessus () {
  #
  ## Parse Nessus result by selecting and executing the right Nessus format parser: i.e. - nbe, Nessus v1, or Nessus v2. 
  #
        my $size_file = -s $opts{file};
        print "Parse Nessus scan result file: $opts{file}\nFile size: $size_file bytes\n";
        if (input_file_is_nbe ) {
		parse_nbe ();
	} elsif ( input_file_is_nessus  eq 2) {
		parse_nessus_v2();			
	} elsif (input_file_is_nessus  eq 1) {
		parse_nessus_v1();			
	} else {
		die "Error! The program input file $opts{file} is not recognized: Unknown Nessus file format. \n"; 
	}
	print "Done parsing Nessus scan result file $opts{file}\n\n";
}

sub parse_nbe () {
  #
  ## Parse Nessus result in nbe format. Save the details into a global hash %FINDINGS, %TIMESTAMPS
  #
	my %levels = ("Security Note", 0,					# Nessus nbe risk scale converting table
           "Security Warning", 2,
           "Security Hole", 3);
	open (IN,$opts{file}) || die "Can't open nbe file $opts{file}: $!";
	while (<IN>) {
		chomp;
		if (/(.*)|(.*)|(.*)|(.*)|(.*)|(.*)|(.*)/){
			my ($type, $net, $system, $service, $plugin_id, $level, $msg) = split(/\|/, $_, 7);
 			if ($type eq "results") {				# Sorting out Nessus finding result and break it down
				if ($verbose) { print "Parsing host: $system ...\n"; }
				$msg=~s/(\\n|\\r)/\t/g;
				my @P=split(/Plugin output :/,$msg);		# Capture of plugin output field in the report - this is less precisely.
				my $plugin_output=$P[1];
				push @{$FINDINGS{$plugin_id}{systems}},$system;
				push @{$FINDINGS{$plugin_id}{services}},$service;
				push @{$FINDINGS{$plugin_id}{plugin_outputs}}, $plugin_output;
				unless ($FINDINGS{$plugin_id}{msg}) {$FINDINGS{$plugin_id}{msg}=$msg;}		# Generic message, only plugin-output is unique 
				unless ($FINDINGS{$plugin_id}{level}) {$FINDINGS{$plugin_id}{level}=$levels{$level};}
			} elsif ($type eq "timestamps") {			# Sorting out the timestamps information
				if ($service eq "host_start") {
					$TIMESTAMPS{$system}{host_start}=$plugin_id;
				} elsif ($service eq "host_end") {
					$TIMESTAMPS{$system}{host_end}=$plugin_id;
				}
			} 
		}
	}
	close (IN);
}
 
sub parse_nessus_v1 () {
  #
  ## Parse Nessus result in Nessus v1 format (xml). Map Nessus v1 data structure into Maverick's. 
  #
	my %levels = ("1", 0,							# Mapping scale back to nbe
           "2", 2,
           "3", 3);
	my $parser=XML::LibXML->new();
	my $doc = $parser->parse_file ($opts{file});
	# Nessus v1 XML DOM tree structure "ReportHost" => "ReportItem | Host Status" => "Report item detail: service, port, data"
	foreach my $report_host ($doc->getElementsByTagName("ReportHost")){
		my $hostname = $report_host->getElementsByTagName('HostName');
		$TIMESTAMPS{$hostname}{host_start}=$report_host->getElementsByTagName('startTime');
		$TIMESTAMPS{$hostname}{host_end}=$report_host->getElementsByTagName('stopTime');
		if ($verbose) { print "Parsing host: $hostname ...\n"; }
		for my $report_item ($report_host->getElementsByTagName("ReportItem")) {				
			my %item;
			for my $report_item_child ($report_item->getChildNodes) {
				my ($name, $value);
				if ($report_item_child->nodeName ne "#text"){
					$name=$report_item_child->nodeName;
					$value=$report_item_child->to_literal;
				}				
				$item{$name} = $value;
			}
			$item{data} =~ s/(\\n|\\r)+/\t/g;
			my @D=split(/Plugin output :/,$item{data});
			if ($D[1]) { 
				$item{plugin_output}=$D[1];
			}
			if ($item{pluginID} ) {
				push @{$FINDINGS{$item{pluginID}}{systems}}, $hostname;
				push @{$FINDINGS{$item{pluginID}}{services}}, $item{port};
				push @{$FINDINGS{$item{pluginID}}{plugin_outputs}}, $item{plugin_output};
				unless ($FINDINGS{$item{pluginID}}{msg}) { 
					$FINDINGS{$item{pluginID}}{msg}=$item{data};		
				}
				unless ($FINDINGS{$item{pluginID}}{level}) {
					$FINDINGS{$item{pluginID}}{level}=$levels{$item{severity}};
				}
			}
		}
	}
	undef $parser;
}

sub parse_nessus_v2 () {
  #
  ## Parse Nessus result in Nessus v2 format (xml). Map Nessus v2 data structure into Maverick's. 
  #
	my %levels = ("1", 0,							
           "2", 2,
           "3", 3);
	my $parser=XML::LibXML->new();
	my $doc = $parser->parse_file ($opts{file});
	# Nessus v2 XML DOM tree structure "Report" => "ReportHost" => "HostProperties | ReportItem" => "tag"
	# Loop over the report hosts to retrieve the timestamp and finding items detail
	foreach my $report_host ($doc->getElementsByTagName("ReportHost")){
		my %host;
		$host{name} = $report_host->getAttribute("name");
		if ($verbose) { print "Parsing host: $host{name} ...\n"; }
		foreach my $host_property ($report_host->getElementsByTagName("HostProperties")){
			foreach my $host_property_tag ($host_property->getChildNodes()){
				if ($host_property_tag->nodeName() ne "#text"){
					my $tag = $host_property_tag->getAttribute("name");
					my $value = $host_property_tag->getFirstChild()->getData;
					$host{$tag} = $value;
				}
			}
			$TIMESTAMPS{$host{name}}{host_start}=$host{HOST_START};
			$TIMESTAMPS{$host{name}}{host_end}=$host{HOST_END};
		}
		# Loop over the ReportItems for the host
		for my $report_item ($report_host->getElementsByTagName("ReportItem")){
			my %item;
			# Retrieve data from ReportItem
			for my $attr (qw{port svc_name protocol severity pluginID pluginName pluginFamily}){
				$item{$attr} = $report_item->getAttribute($attr);
			}
			# Retrive data from child elements of ReportItem
			for my $report_item_child (qw{xref bid plugin_output vuln_publication_date cvss_vector cvss_score cve description risk_factor cvss_base_score plugin_publication_date solution plugin_version synopsis see_also patch_publication_date exploit_available cvss_temporal_score cvss_temporal_vector }){
				my @values;
				for my $node ($report_item->getElementsByTagName ($report_item_child)){
					if ($node->nodeName() ne "#text"){
						push @values, $node->getFirstChild()->getData();
					}
				}
				$item{$report_item_child} = join ",", @values;
				if ($report_item_child eq "xref" || $report_item_child eq "cve" || $report_item_child eq "see_also" || $report_item_child eq "bid"){
					$item{$report_item_child."_array"} = \@values;
				}
			}		
			# Clean the text format
			$item{synopsis} =~ s/(\r|\n)/\t/g;
			$item{description} =~ s/(\r|\n)/\t/g;
			$item{solution} =~ s/(\r|\n)/\t/g;
			$item{plugin_output} =~ s/(\r|\n)/\t/g;
			# Map back to Maverick's data structure
			my $service = $item{svc_name}." (". $item{port}."/".$item{protocol}.")";
			my $msg = "Synopsis:\t". $item{synopsis}. "\tDescription: ". $item{description}. "\tSee also : @{$item{see_also_array}}" . "\tSolution: " . $item{solution} . "\tRisk factor: " . $item{risk_factor}. "\tCVSS Base Score: " . $item{cvss_base_score}. " (" . $item{cvss_vector}. ") CVSS Temporal Score: ". $item{cvss_temporal_score}. " (".$item{cvss_temporal_vector}. ")\tCVE : ". "@{$item{cve_array}}". "BID : "."@{$item{bid_array}}";
			if ($item{xref}) {
				$msg=$msg. "\tOther references: ". "@{$item{xref_array}}";
			}
			if ($item{exploit_available}) {
				$msg = $msg . "\tPublic Exploit Available: " . $item{exploit_available};
			}
			if ($item{plugin_output}) {
				$msg = $msg. "\tPlugin output : ".$item{plugin_output};
			}
			push @{$FINDINGS{$item{pluginID}}{systems}}, $host{name};
			push @{$FINDINGS{$item{pluginID}}{services}}, $service;
			push @{$FINDINGS{$item{pluginID}}{plugin_outputs}}, $item{plugin_output};
			unless ($FINDINGS{$item{pluginID}}{msg}) { $FINDINGS{$item{pluginID}}{msg}=$msg;	}	
			unless ($FINDINGS{$item{pluginID}}{exploitable}) { $FINDINGS{$item{pluginID}}{exploitable}= $item{exploit_available}; }
			unless ($FINDINGS{$item{pluginID}}{level}) { $FINDINGS{$item{pluginID}}{level}=$levels{$item{severity}}; }					
		}
	}
	undef $parser;							
}

sub print_nessus_report () {
  #
  ## Print out the sorted Nessus report.  The result is grouped by plug-in id and sorted by severity level descendingly. 
  ## If optional '-mapping' command switch is on, Maverick will do additional step to map the Nessus findings to the BT EHCOE repository (excel template).
  #
	# Prepare to save the output into the file defined by the user if any
	unless (defined $opts{mapping}) {
		if (defined $opts{output}) { open (OUT, ">", $opts{output}) || die " Can't open the file 1: $opts{output} : $!\n"; }
	}
	# Check for the optional '-mapping' command switch. If exist read the mapping configuration file.
	if ($opts{mapping}) {
		if (-e $opts{mapping}) { 
			read_config_simple($mapping);
		} else {
			die "Missing mapping configuration file $opts{mapping}: $!\n";
		}
		print "Easy Reporting Engine is now activated:\n";  
		print "Welcome to the Easy Reporting Engine. This engine will help you generate a BT baseline report quickly. This is done by pulling out all known write-ups from the BT EHCOE repository for you. There will be two parts in the program output. For the first part, you will have a BT baseline report titled $CNF{xls_report} with all the matches. For the second part, any un-mapped Nessus finding is still piped to either the console, or a text file for your further scrutiny. Be sure to go through the second part carefully to avoid any missing. In such case, please remember to reeport back the missing detail to author. So that it could be corrected in the future release. \n\n";
		if ($CNF{xls_repository}) {
			nessus_2_xls_repository(); 
		} elsif ($CNF{xml_repository}) {
			index_xml_repository();
			nessus_2_xml_repository();
		} else {
			die "Error! EHCOE finding repository is not defined in the mapping configuration file: $opts{mapping}.\n";
		}
	} else {		# Otherwise business is usual - print out the findings (to stdout or output file)
		# Check for the optional '-output' command switch. If exist pipe the result to the output file.
		if (defined $opts{output}) {
			print "Save the un-matched findings into file: $opts{output} ... \n";
			foreach my $pid (sort {$FINDINGS{$b}{level} <=> $FINDINGS{$a}{level}} keys %FINDINGS) {
				print OUT "\n\nNessus Plugin ID: $pid\n";
				print OUT "Risk Level: ";
				if ($FINDINGS{$pid}{level} > 2) {
					print OUT "High\n";
				} elsif ($FINDINGS{$pid}{level} >0) {
					print OUT "Medium\n";
				} else {
					print OUT "Low\n";
				}
				$FINDINGS{$pid}{msg} =~ s/(\\n|\\r)/\t/g;
				print OUT "Affected System(s):\n";
				foreach (@{$FINDINGS{$pid}{systems}} ){ print  OUT "$_\n";}
				print OUT "Affected Service(s):\n";
				foreach (@{$FINDINGS{$pid}{services}} ) { print OUT "$_\n";}
				print OUT "Vulnerability Details: \n\t$FINDINGS{$pid}{msg}\n";
			}
			print "Done saving into $opts{output}.\n";
		} else {		# Or just pipe the output to the stdout if nothing defined
			foreach my $pid (sort {$FINDINGS{$b}{level} <=> $FINDINGS{$a}{level}} keys %FINDINGS) {
				print "\n\nNessus Plugin ID: $pid\n";
				print "Risk Level: ";
				if ($FINDINGS{$pid}{level} > 2) {
					print "High\n";
				} elsif ($FINDINGS{$pid}{level} >0) {
					print "Medium\n";
				} else {
					print "Low\n";
				}
				$FINDINGS{$pid}{msg} =~ s/(\\n|\\r)/\t/g;		
				print "Affected System(s):\n"; 
				foreach (@{$FINDINGS{$pid}{systems}} ){ print "$_\n";}
				print "Affected Service(s):\n"; 
				foreach (@{$FINDINGS{$pid}{services}} ) { print "$_\n";}
				print "Vulnerability Details: \n\t$FINDINGS{$pid}{msg}\n";
			}
		}
	}
	if (defined OUT) { 						
		#print "Done saving findings to file:\t$opts{output}\n";
		close (OUT); 
	}				
}

sub print_exploitable_report () {
  #
  ## Parse Nessus v2 file and print out exploitable findings only
  #
	if (input_file_is_nessus()) {
		parse_nessus();
	} else {
		die "Error! Sorry only Nessus v2 format is supported for this feature.\n";
	}
	if (defined $opts{output}) { 
		open (OUT, ">", $opts{output}) || die " Can't open the file 2: $opts{output} : $!\n";  
		if ($verbose) { print "Save the findings into file: $opts{output} ... \n"; }
		foreach my $pid (sort {$FINDINGS{$b}{level} <=> $FINDINGS{$a}{level}} keys %FINDINGS) {
			if ($FINDINGS{$pid}{exploitable} eq "true") {
				print OUT "\n\nNessus Plugin ID: $pid\n";
				print OUT "Risk Level: ";
				if ($FINDINGS{$pid}{level} > 2) {
					print OUT "High\n";
				} elsif ($FINDINGS{$pid}{level} >0) {
					print OUT "Medium\n";
				} else {
					print OUT "Low\n";
				}
				# Format contents before printing out
				$FINDINGS{$pid}{msg} =~ s/(\n|\r)/\t/g;	
				print OUT "Affected System(s): \n";
				foreach (@{$FINDINGS{$pid}{systems}}) { print OUT "$_\n"; }
				print OUT "Affected Service(s): \n";
				foreach (@{$FINDINGS{$pid}{services}}) { print OUT "$_\n"; }
				print OUT "Vulnerability Details:\n\t$FINDINGS{$pid}{msg}\n";		
			}
		}
		print "Done saving exploitable findings into report:\t$opts{output}.\n";
	} else {		# Or just pipe the output to the stdout if nothing defined
		foreach my $pid (sort {$FINDINGS{$b}{level} <=> $FINDINGS{$a}{level}} keys %FINDINGS) {
			if ($FINDINGS{$pid}{exploitable} eq "true") {
				print "\n\nNessus Plugin ID: $pid\n";
				print "Risk Level: ";
				if ($FINDINGS{$pid}{level} > 2) {
					print "High\n";
				} elsif ($FINDINGS{$pid}{level} >0) {
					print "Medium\n";
				} else {
					print "Low\n";
				}
				# Format contents before printing out
				$FINDINGS{$pid}{msg} =~ s/(\n|\r)/\t/g;	
				print "Affected System(s): \n";
				foreach (@{$FINDINGS{$pid}{systems}}) { print "$_\n"; }
				print "Affected Service(s): \n";
				foreach (@{$FINDINGS{$pid}{services}}) { print  "$_\n"; }
				print "Vulnerability Details:\n\t$FINDINGS{$pid}{msg}\n";
			}
		}
	}
}

sub print_nessus_timestamps () {
  #
  ## Print out the Nessus timestamps summary report. I.E. which hosts were scanned, when were they started, were they completed etc..
  #
  	if (input_file_is_nbe()) { 
		parse_nbe ();
	} elsif (input_file_is_nessus()) {
		parse_nessus();
	} else {
		die "Error! Unknown Nessus format for this program feature. \n";
	}
	# Check if the optional command switch "-output" is defined, and get ready for it if so.
	if (defined $opts{output}) { 
		open (OUT, ">", $opts{output}) || die " Can't open the file 3: $opts{output} : $!\n"; 
		print OUT "Table of Nessus Scan Timestamps\n";
		print OUT "Scanned IP\tStart\t\t\t\tEnd\n";
	} else {
		print "Table of Nessus Scan Timestamps\n";
		print "Scanned IP\tStart\t\t\t\tEnd\n";
	}		
	foreach my $key (sort keys %TIMESTAMPS) {
		if ($opts{output}) {
			print OUT "$key\,\t$TIMESTAMPS{$key}{host_start}\,\t$TIMESTAMPS{$key}{host_end}\n";
		} else {
			print "$key\,\t$TIMESTAMPS{$key}{host_start}\,\t$TIMESTAMPS{$key}{host_end}\n";
		}
	}
	if (defined $opts{output}) {						
		close (OUT); 
		print "Done saving timestamp table into file:\t$opts{output}\n";
	}				
	exit 0;
}

sub dump_weak_ciphers () {
  #
  ## Search Nessus report for plugin-id 26928,42873, which containsParse weak ciphers information. And dump out such information
  ## into a table (In BT EHCOE reporting format)
  #
	# Check if the optional command switch "-output" is defined, and get ready for it if so.
	unless (defined $opts{mapping}) {
		if (defined $opts{output}) { 
			open (OUT, ">", $opts{output}) || die " Can't open the file 4: $opts{output} : $!\n"; 
		}
	}
	my @PIDS=("26928", "42873");		# Plugin-ID for 'medium(56-112 bits)' and 'weak(<56bits)' strengh ciphers
	#our %WC;				# Hash to store weak cipher table
	foreach (@PIDS) {
		chomp;
		$pid1=$_;
		my @SYSTEMS=@{$FINDINGS{$pid1}{systems}};
		my @SERVICE=@{$FINDINGS{$pid1}{services}}; 
		my @PLUGIN_OUTPUT=@{$FINDINGS{$pid1}{plugin_outputs}};
		for (my $i=0;$i<=$#SYSTEMS;$i++) {
			search_weak_cipher ($SYSTEMS[$i], $SERVICE[$i], $PLUGIN_OUTPUT[$i]);
		}
	}
	if (defined OUT) { close (OUT); }
}

sub print_weak_cipher_table () {
  #
  ## print out the result
  #
	if (defined $opts{output}) {
		# Printing outcome in CSV table format, separated by colon ":"
		print OUT "\nTable of Found Weak Ciphers\n";
		print OUT "IP\t\:\tPort\t\:\tProtocols\t\:\tCipher Suites with Weak Encryption\n";
		for my $key ( keys %WC ) {
			print OUT "$key : $WC{$key}{prot}: $WC{$key}{cipher} \n";
		}
	} else {	
		# Printing outcome in CSV table format, separated by ":"
		print "\nTable of Found Weak Ciphers\n";
		print "IP\t\:\tPort\t\:\tProtocols\t\:\tCipher Suites with Weak Encryption\n";
		for my $key ( keys %WC ) {
			print "$key : $WC{$key}{prot}: $WC{$key}{cipher} \n";
		}
	} 
	if (defined $opts{output}) {						
		print "Done saving weak ciphers to file:\t$opts{output}\n"; 
		close (OUT); 
	}				
	exit (0);	
}

sub search_weak_cipher () {
  #
  ## Extract weak ciphers from Nessus message body and save them into a global hash %WC
  #
	if ($_[1] =~ /(\d+)/) { 						# Extract service port num only
		$key=$_[0].":".$1;
	}
	if ($verbose) { print "Start searching weak ciphers on $key within this Nessus message: $_[2]...\n"; }
	my $pout;
	if (input_file_is_nbe()) {
		my @M=split('supported by the remote server',$_[2]);		# Truncating with unique message string 
		my @N=split('The fields above are :',$M[1]);			
		$pout=$N[0];
		if ($verbose) { print "Processing $pout\n"; }
	} elsif (input_file_is_nessus() ) {
		$pout=$_[2];
	}
	if ($pout=~/SSLv2/) {
		my $fnd=0;
		my @T=split(/,/, $WC{$key}{prot});
		foreach(@T) { if (/SSLv2/) { $fnd++; }	}
		unless ($fnd) { 
			$WC{$key}{prot}.="SSLv2,"; 
			if ($verbose) { print "Found SSLv2\n"; }
		}
	} 
	if ($pout=~/SSLv3/) {
		my $fnd=0;
		my @T=split(/,/, $WC{$key}{prot});
		foreach(@T) { if (/SSLv3/) { $fnd++; } }
		unless ($fnd) { 
			$WC{$key}{prot}.="SSLv3,"; 
			if ($verbose) { print "Found SSLv3\n"; }
		}
	} 
	if ($pout=~/TLSv1/) {
		my $fnd=0;
		my @T=split(/,/, $WC{$key}{prot});
		foreach(@T) { if (/TLSv1/) { $fnd++; }	}
		unless ($fnd) { 
			$WC{$key}{prot}.="TLSv1,"; 
			if ($verbose) { print "Found TLSv1\n"; }
		}
	} 
	# Now let's extract the ciphers
	while ( $pout =~  /(.{2,7}-.{2,7}-.{2,7}-.{2,7}-.{2,7} || .{2,7}-.{2,7}-.{2,7}-.{2,7} || .{2,7}-.{2,7}-.{2,7} || NULL-.{2,7})/g ) { 
		if ($1) {
			my $fnd=0; 
			my $cp=$1;  
			$cp=~s/\s//g;
			if ($verbose) { print "Found weak cipher: $cp\n"; }
			my @P=split(/,/,$WC{$key}{cipher});
			foreach (@P) {
				chomp;s/ //g;
				if ($_ eq $cp) { $fnd++; }
			}
			unless($fnd && $cp) {
				$WC{$key}{cipher} = $WC{$key}{cipher}.$cp.",";
			}
		}
	}
}

sub dump_web_svr_type () {
  #
  ## Search Nessus report for plugin-id 10107, which contains web server type in the plugin output field. And dump out such
  ## information for all affected hosts(BT EHCOE report requirement)
  #
  	if (input_file_is_nbe()) { 
		parse_nbe ();
	} elsif (input_file_is_nessus()) {
		parse_nessus();
	} else {
		die "Command switch error. Un-supported input file $opts{file} for this command action: $opts{action} \n";
	}
	# Check if the optional command switch "-output" is defined, and get ready for it if so.
	if (defined $opts{output}) { open (OUT, ">", $opts{output}) || die " Can't open the file 5: $opts{output} : $!\n"; }
	my $pid1 = 10107;							# This is the hardcoded nessus plugins ID for detected web services.
	my %WT;									# Hash to store web server type table
	my @SYSTEMS=@{$FINDINGS{$pid1}{systems}};
	if ($verbose) { print "List of systems under this plugin: @SYSTEMS\n"; }  
	my @SERVICES=@{$FINDINGS{$pid1}{services}}; 
	if ($verbose) { print "List of services under this plugin: @SERVICES\n"; } 
	my @PLUGIN_OUTPUTS=@{$FINDINGS{$pid1}{plugin_outputs}};
	if ($verbose) { print "List of plugin output under this plugin: @PLUGIN_OUTPUTS\n"; }
	my $key;
	for (my $i=0;$i<=$#SYSTEMS;$i++) {						
		my $system=$SYSTEMS[$i];
		if ( $SERVICES[$i] =~ /\((\d+)/ ) {				# Extract service port num only
			$key=$system.":".$1;
			#print $key, "\n";
		}
		if ( input_file_is_nbe() || input_file_is_nessus() ) {
			my @T=split(/The remote web server type is :/,$PLUGIN_OUTPUTS[$i]);
			my $value=$T[1];
			$value =~ s/\\n//g;
			if ($value) { 
				$WT{$key}=$value; 				# Save to the hash %WT
			}
		} 
	}
	if (defined $opts{output}) {
		# Print outcome in CSV table format, with seperator ":"
		print OUT "\nTable of Found Web Servers\n";
		print OUT "System\t\:\tPort\t\:\tWeb Server Type\n";
		for my $key ( keys %WT ) {
			print OUT "$key : $WT{$key}\n";
		}
	} else {								# Piped to stdout if '-output' command switch not defined
		print "\nTable of Found Web Servers\n";
		print "System\t\:\tPort\t\:\tWeb Server Type\n";
		for my $key ( keys %WT ) {
			print "$key : $WT{$key}\n";
		}
	}
	if (defined $opts{output}) {					
		print "Save web server type detail to file:\t$opts{output} ... Done!\n";
		close (OUT); 
	}
	exit (0);	
}

sub dump_web_software () {
  #
  ## Search Nessus report for plugin-id 24260, which contains web server engine software detail in the plugin output field. And dump out such
  ## information (i.e. "x-powered-by: ASP.NET 1.x") for all affected hosts(BT EHCOE report requirement)
  #
	 if (input_file_is_nbe()) { 
		parse_nbe ();
	} elsif (input_file_is_nessus()) {
		parse_nessus();
	} else {
		die "Command switch error. Un-supported input file $opts{file} for this command action: $opts{action} \n";
	}
	# Check if the optional command switch "-output" is defined, and get ready for it if so.
	if (defined $opts{output}) { open (OUT, ">", $opts{output}) || die " Can't open the file 6: $opts{output} : $!\n"; }
	# This is the hardcoded nessus plugins ID for detected web services. 
	my $pid1 = 24260;
	my %WSW;								# Hash to store found web engine softwares
	my @SYSTEMS=@{$FINDINGS{$pid1}{systems}};
	if ($verbose) { print "List of systems under this plugin: $FINDINGS{$pid1}{systems} \n"; }  
	my @SERVICE=@{$FINDINGS{$pid1}{services}}; 
	my @PLUGIN_OUTPUT=@{$FINDINGS{$pid1}{plugin_outputs}};
	my $key;
	for (my $i=0;$i<=$#SYSTEMS;$i++) {						
		my $ip=$SYSTEMS[$i];
		if ( $SERVICE[$i] =~ /\((\d+)/ ) {				# Extract service port num only
			$key=$ip.":".$1;
		}
		my @T=split(/X-Powered-By:/,$PLUGIN_OUTPUT[$i]);
		my @S=split(/\\r\\n/,$T[1]);
		if ($S[0]) { 
			$WSW{$key}=$S[0]; 					# Save to a hash %WSW
		}	
	}	
	if (defined $opts{output}) {	
		# Print outcome in CSV table format, with seperator ":"
		print OUT "\nTable of Found Web Engine Softwares\n";
		print OUT "IP\t\:\tPort\t\:Web Engine Software\n";
		for my $key ( keys %WSW ) {
			print OUT "$key : $WSW{$key}\n";
		}
	} else {								# Piped to stdout if '-output' command switch not defined
		print "\nTable of Found Web Engine Softwares\n";
		print "IP\t\:\tPort\t\:\tWeb Engine Software\n";
		for my $key ( keys %WSW ) {
			print "$key : $WSW{$key}\n";
		}
	}
	if (defined $opts{output}) {						
		close (OUT); 
		print "Done saving websoftware type detail to file:\t$opts{output}\n";	
	}
	exit (0);	
}

sub dump_plugin_output () {
  #
  ## Search Nessus report for a specific plugin. And dump out plugin output content for all affected hosts line by line.
  #
	if (input_file_is_nbe()) { 
		parse_nbe ();
	} elsif (input_file_is_nessus()) {
		parse_nessus();
	} else {
		die "Command switch error. Un-supported input file $opts{file} for this command action: $opts{action} \n";
	}
	# Check if the optional command switch "-output" is defined, and get ready for it if so.
	if (defined $opts{output}) { open (OUT, ">", $opts{output}) || die " Can't open the file 7: $opts{output} : $!\n"; }
	# This is the hardcoded nessus plugins ID for detected web services. 
	unless ($opts{pid} and $opts{file} ) { 
		die "Error command switch: You need to supply a valid Nessus plugin ID via '-pid', and a valid Nessus file via '-file' \n";
	}		
	if ($FINDINGS{$opts{pid}}{plugin_outputs}) {
		if ($verbose) { print "List of systems under this plugin: $FINDINGS{$opts{pid}}{systems} \n"; }  
		#if ($verbose) { print "List of Plugin-outputs under this plugin: $FINDINGS{$opts{pid}}{plugin_outputs} \n"; }  
		$FINDINGS{$opts{pid}}{plugin_outputs} =~ s/(\\n|\\r)/\t/g;	# Replace CR and LF char for better appearance
		my @SYSTEMS=@{ $FINDINGS{$opts{pid}}{systems} };
		my @SERVICE=@{$FINDINGS{$opts{pid}}{services}}; 
		my @PLUGIN_OUTPUT=@{$FINDINGS{$opts{pid}}{plugin_outputs}};
		my $port;
		if ($opts{output}) {
			print OUT "Table of Nessus ID $opts{pid} Plugin Outputs \n";
			print OUT "IP\t:\tPort\t:Plugin Output\n";
		} else {
			print "Table of Nessus ID $opts{pid} Plugin Outputs \n";
			print "IP\t:\tPort\t:Plugin Output\n";
		}
		for (my $i=0;$i<=$#SYSTEMS;$i++) {
			if ( $SERVICE[$i] =~ /\((\d+)/ ) {
				$port = $1;
			}
			if ($opts{output}) {
				print OUT "$SYSTEMS[$i] : $port : $PLUGIN_OUTPUT[$i]\n";
			} else {
				print "$SYSTEMS[$i] : $port : $PLUGIN_OUTPUT[$i]\n";
			}
		}
	} else {
		die "Plugin ID $opts{pid} can not be found in $opts{file}: $!\n";
		exit 1;
	}
	if (defined $opts{output}) {						
		close (OUT); 
		print "Done saving plugin output detail to file:\t$opts{output}\n";
		exit (0);	
	} 
}

sub exec_nikto () {
  #
  ## Parse Nessus result file. And perform Nikto audit on all found http(s) servers in one shot. Notice you need to install and configure 
  ## Nikto 2.1.3 and above before using this feature   
  #
	if (input_file_is_nbe()) { 
		parse_nbe ();
	} elsif (input_file_is_nessus()) {
		parse_nessus();
	} else {
		die "Command switch error. Un-supported input file $opts{file} for this command action: $opts{action} \n";
	}
	$nikto=locate_nikto ($opts{path});					# Automatically search for the right nikto executable
        die "\nNikto is not in the path: $nikto,  or not executable: $!\n" unless (-x $nikto);
	my $pid1=22964;                                                         # Nessus plugins ID for detected services
	my %WS;									# Hash to store http/https service table
	my @SYSTEMS=@{$FINDINGS{$pid1}{systems}};
	my @SERVICE=@{$FINDINGS{$pid1}{services}}; 
	my $key;
	for (my $i=0;$i<=$#SYSTEMS;$i++) {	
		my ($web,$ssl,$port,$key);
		if ($SERVICE[$i] =~ /(http|www)/) {
			$web=1;
			$ssl=is_ssl_enable($SYSTEMS[$i], $SERVICE[$i]);
			if ($SERVICE[$i] =~ /\((\d+)/) {
				$port = $1;
			}
		} else {
			$web=0;
		}
		if ($web && $port) {
			if ($verbose) {	print "Identified web server system: $SYSTEMS[$i], Port: $port, SSL: $ssl\n"; }
			$key=$SYSTEMS[$i]."_".$port;
			$WS{$key}=$ssl;						# Using hash to eleminate duplicate web server entry
		}		
	}
	print "Please be patient while nikto is running in the background. Do ps to make sure all nikto processes are finished. Then you'll see nikto output files under the same folder.\n...\n";
        sleep(5);
        # Execute Nikto one by one
	for my $key ( keys %WS ) {
		if ($verbose) { print "$key : $WS{$key}\n"; }
		my $file_out = $key . "_nikto". ".txt";
		my ($ip,$port) = split(/_/,$key);
		if ( $WS{$key} ) {
			print ("Execute Nikto command now: $nikto -host $ip -port $port -ssl -output $file_out &\n");
			system ("$nikto -host $ip -port $port -ssl -output $file_out &");
		} else {
			print ("Execute Nikto command now: $nikto -host $ip -port $port -output $file_out &\n");
			system ("$nikto -host $ip -port $port -output $file_out &");
		}
	}
	exit (0);
}

sub is_ssl_enable () {
  #
  ## Search hash table %FINDINGS to determine if ssl is enable on the specific IP and Service Port.
  #
	my $pid=24260;								# Nessus plugin to test remote HTTP protocol 
	my $ssl=0;
	my @SYSTEMS=split(/\|/, $FINDINGS{$pid}{systems});
	my @SERVICES=split(/\|/, $FINDINGS{$pid}{services});
	my @POUT=split(/\|/, $FINDINGS{$pid}{plugin_outputs});
	for (my $i=0;$i<=$#SYSTEMS;$i++) {
		if (($SYSTEMS[$i] eq $_[0]) && ($SERVICES[$i] eq $_[1])) {
			if ($POUT[$i] =~ /SSL\s+:\s+yes/) {
				$ssl++;
				return $ssl;
			}
		}
	}
	return $ssl;
}

sub locate_nikto () {
  #
  ## Automactically earch for the right Nikto executable for Maverick, and return its absolute path.
  #
	my @bin=("nikto.pl", "nikto");
	# Search shell environment $PATH variable for possible Nikto installation
	my $path_sh= `echo \$PATH`;  
	my @PATH=split(/\:/,$path_sh);
	push (@PATH, $_[0]);
	foreach (@PATH) {
		chomp; 
		my $path=$_;
		foreach (@bin) {
			chomp;s/\s//g;
			my $bin=$_;
			my $nikto=$path."/".$bin;
			if (-x $nikto) {
				return $nikto;
			}
		}
	}
	return "UNFOUND";
}

sub parse_nmap_terse () {
  #
  ## Parse nmap result in xml format. Only open ports are kept. Session info and close ports are tossed away.
  #	
	# Check if the optional command switch "-output" is defined, and get ready for it if so.
	if (defined $opts{output}) { open (OUT, ">", $opts{output}) || die " Can't open the file 8: $opts{output} : $!\n"; }
	my $np=new Nmap::Parser;
	$np->parsefile($opts{file});
	my @HOST=$np->all_hosts("up");						# List of 'up' hosts
	if (defined $opts{output}) {
		print OUT "\nTable of Found Open Ports\n";
		print OUT"IP	Port	Status	Service	OS	Hostname\n";
		for my $up_host (@HOST){
			$os = $up_host->os_sig; $osname=$os->name;
			my $ip=$up_host->addr; my $hostname=$up_host->hostname();
			print  OUT "$ip\t\t\t\t$osname\t$hostname,\n"; 		# Addr: $up_host->addr, OS: $up_host->os_sig\n";	
			my @p_tcp=$up_host->tcp_open_ports;
			my @p_udp=$up_host->udp_open_ports;
			foreach(@p_tcp) {					# Print list of open tcp ports
				my $state=$up_host->tcp_port_state($_);
				my $svc = $up_host->tcp_service($_);
				my $svc_name = $svc->name;
				print OUT "\t$_\/tcp\t$state\t$svc_name\n";
			}
			foreach(@p_udp) {					# Print list of open udp ports
				my $state=$up_host->udp_port_state($_);
				my $svc = $up_host->udp_service($_);
				my $svc_name = $svc->name;
				print OUT "\t$_\/udp\t$state\t$svc_name\n";
			}
		}
	} else {		# Redirect to stdout if '-output' command switch is not defined
		print "\nTable of Found Open Ports\n";
		print "IP	Port	Status	Service	OS	Hostname\n";
		for my $up_host (@HOST){
			$os = $up_host->os_sig; $osname=$os->name;
			my $ip=$up_host->addr; my $hostname=$up_host->hostname();
			print "$ip\t\t\t\t$osname\t$hostname,\n"; # addr: $up_host->addr, OS: $up_host->os_sig\n";	
			my @p_tcp=$up_host->tcp_open_ports;
			my @p_udp=$up_host->udp_open_ports;
			foreach(@p_tcp) {					# Print list of open tcp ports
				my $state=$up_host->tcp_port_state($_);
				my $svc = $up_host->tcp_service($_);
				my $svc_name = $svc->name;
				print "\t$_\/tcp\t$state\t$svc_name\n";
			}
			foreach(@p_udp) {					# Print list of open udp ports
				my $state=$up_host->udp_port_state($_);
				my $svc = $up_host->udp_service($_);
				my $svc_name = $svc->name;
				print "\t$_\/udp\t$state\t$svc_name\n";
			}	
		}
	}
	if (defined $opts{output}) {
		close (OUT);  				
		print "Done dumping out open ports table from $opts{file} to: $opts{output}.\n";
	}
	undef $np;
}

sub lookup_as_number () {
  #
  ## Perform AS number lookup for the IP blocks. Print out the table sorted by AS name
  #
	my @L_IPS = filter_whois_lookup($opts{ips});
	foreach (@L_IPS) {
		lookup_as_cymru($_);
	}
	# print out AS number table sorted by AS name
	print "\nAS Name		|	AS Number		|	IP(s)\n";
	foreach my $key (sort (keys %AS)) {
		my $val=$AS{$key};
		print "$key	|	$val\n";
	}
}

sub audit_ip_blocks () {
  #
  ## Perform IP blocks audit for client's domain. 
  # 
	# Program output file for tracking
	my $file_out=defined $opts{output} ? $opts{output} : '/tmp/.out';	# default program output to file '/tmp/.out'
	#open (OUT, ">$file_out") || die "Can't open file: $file_out $!\n";	
	#print OUT "$opts{domain} exception list:\n";
	# Extract client's domain information
	if ($opts{domain}) {
		my $domainname = url_2_domainname($opts{domain});		# url support - extract domain info from client's url 
		our $domain_root=lookup_domain_root($domainname);
		$UDK=substr($domain_root,0,3);
	} else { 
		print "Program exit: please supply a valid domain name. \n"; exit(1); 
	}
	########################################################################
	# IMPORTANT!!! CLIENT IP BLOCKS AUDIT (MATCHING) ALGORITHM 
	# We use a Unique Domain Key (UDK) string for whois lookup result parsing. For instance, UDK is used
	# to seperate client's net blocks from its ISP's. By default, this unique string is the first 3 letters of client's domain name. 
	# However, UDK could be reset by user during the execution of the program, for example, to first 3 letters of 'OrgName' of client's domain. 
	# For example, we will use 'yah' from 'yahoo.com' as the UDK to differentiate 'yahoo.com' netblocks from its ISP's when performing netblocks lookup
	########################################################################	
	# optional - allow user to override UDK from STDIN
	print "\nPlease enter the 3 letters Unique Domain Key (UDK) for $domain_root, or press 'Enter' for default '$UDK': ";
	chomp($answer=<STDIN>);
	if (length($answer) == 3) { 
		$UDK=$answer; 
	}
	unless(length($UDK) ==3) { die "Program exit because of non valid UDK: $UDK\n"; exit(1); }
	# Perform network blocks lookup from program input list; then save results to @NETBLKS
	my @L_IPS = filter_whois_lookup($opts{ips});
	foreach (@L_IPS) {
		@BLK=lookup_net_block($_,$UDK);		
		if (@BLK) { @NETBLKS=Net::CIDR::cidradd(@BLK,@NETBLKS); }
	}
	# Perform range check on the input list. If the element is not within the known range @NETBLKS, then print out a warning
	my @EXCEPTION;
	my @IPS = filter_input_ip_list($opts{ips});
	print "\n\n";
	foreach (@IPS) {
		my $element=$_;
		my $found=Net::CIDR::cidrlookup($element,@NETBLKS);
		if (!$found) {
			print OUT "$element\n";
			print "Whois Audit Warning:\n$element does not belong to $domain_root. \n";
			print "Please verify $element with your client. \n";
			push (@EXCEPTION, $element);
		}
	}
	# If every element pass the test, then print out confirmation.
	if (!@EXCEPTION) {
		print "\n\nSuccess:\n@IPS are all confirmed to belong to client $domain_root. \n";
	}
 	#close(OUT);
}

sub filter_whois_lookup () {
  #
  ## Preparing IP input list in comma seperated format. Return the IPs in an array
  ## For netblock such as 216.53.7.0/24, return the first IP 216.53.7.0
  #
	my @L_IPS;
	my @IPS=split (/,/,$_[0]);
	foreach (@IPS) {
		my $ip;
		if ( m/(\d+\.\d+\.\d+\.\d+\/\d+)/g) {				# Looking for x.x.x.x/x only
			$ip=$1;
		} elsif ( m/(\d+\.\d+\.\d+\.\d+)/g) {				# Looking for x.x.x.x only
			$ip=$1;
		}
		my @IP=split(/\//,$ip);						# for emaple 216.53.7.0/24
		my $host=$IP[0];						# extract 216.53.7.0
		push (@L_IPS,$host);
	}
	return @L_IPS;
}

sub filter_input_ip_list () {
  #
  ## Preparing IP target list in Comma Separated Value format (CSV). Return valid elements only.
  #
	my @L_IPS;
	my @IPS=split (/,/,$_[0]);
	foreach (@IPS) {
		if ( m/(\d+\.\d+\.\d+\.\d+\/\d+)/g) {				# Looking for x.x.x.x/x only
			$host=$1;
		} elsif ( m/(\d+\.\d+\.\d+\.\d+)/g) {				# Looking for x.x.x.x only
			$host=$1;
		}
		push (@L_IPS,$host);			
	}
	return @L_IPS;
}

sub lookup_net_block () {
  #
  #  Perform recursive whois lookup on the IP. Return matched network block 
  #     
	my $ip=$_[0];
	my $UDK=$_[1];
	my @blcok; my $nets; my$net_all;
	# Determine the right whois server for querying
	my @root=split(/\./,$domain_root);
	my $whois=lookup_whois_server($ip,$root[@root-1]);
	if ( $whois =~ m/ripe/i ) {
		$nets=lookup_netblk_ripe($ip,$UDK);
       		$nets_all=$nets_all.",".$nets;
       	} elsif ( $whois =~ m/twnic/i ) {
       		$nets=lookup_netblk_twnic($ip);
       		$nets_all=$nets_all.",".$nets;
       	} else {
		$nets=lookup_netblk_arin($ip,$UDK);
		$nets_all=$nets_all.",".$nets;
	}
	# use Net::CIDR method to concatenate net blocks
	@block=split(/,/,$nets_all);
	my @blk;
	foreach (@block) {
		if (m/\d+\.\d+\.\d+\.\d+\/\d+/) {
			@blk=Net::CIDR::cidradd($_,@blk);
		}
	}
	@block=@blk;
	return @block;
}

sub url_2_domainname () {
  #
  ## Extract the Fully Qualified Domain Name(FQDN) from the url string. For example, return 
  #  "login.yahoo.com" from url string "https://login.yahoo.com/config/login_verify2?&.src=ym"
  #  
	if ($_[0] =~ m/http(|s)\:\/\//i) {					# "http(s)://login.yahoo.com/config"
		my @URL=split(/:\/\//, $_[0]);
		my @FQDN=split(/\//,$URL[1]);
   		my $fqdn=$FQDN[0];
		return $fqdn;
	} elsif ($_[0] =~ m/\//) {						# "login.yahoo.com/config/login_verify2?&.src=ym"
     		my @URL=split(/\//, $_[0]);
		my $fqdn=$URL[0];
		return $fqdn;
	} else {
		return $_[0];							# "login.yahoo.com"
	}
}

sub lookup_domain_root () {
  # 
  ## search the domain root for an url. For example, return "yahoo.com" as root domain for "login.yahoo.com"
  #
	# general top level domain list
	my @gtld=qw(net com org gov edu mil biz info aero coop museum name pro mobi);
	# country code top level domain list
	my @cctld=qw(ac  ad  ae  af  ag  ai  al  am  an  ao  aq  ar  as  at  au  aw  ax  az  ba  bb  bd  be  bf  bg  bh  bi  bj  bm  bn  bo  br  bs  bt  bw  by  bz  ca  cc  cd  cf  cg  ch  ci  ck  cl  cm  cn  co  cr  cu  cv  cx  cy  cz  de  dj  dk  dm  do  dz  ec  ee  eg  er  es  et  eu  fi  fj  fk  fm  fo  fr  ga  gd  ge  gf  gg  gh  gi  gl  gm  gn  gp  gq  gr  gs  gt  gu  gw  gy  hk  hm  hn  hr  ht  hu  id  ie  il  im  in  io  iq  ir  is  it  je  jm  jo  jp  ke  kg  kh  ki  km  kn  kp  kr  kw  ky  kz  la  lb  lc  li  lk  lr  ls  lt  lu  lv  ly  ma  mc  md  me  mg  mh  mk  ml  mm  mn  mo  mp  mq  mr  ms  mt  mu  mv  mw  mx  my  mz  na  nc  ne  nf  ng  ni  nl  no  np  nr  nu  nz  om  pa  pe  pf  pg  ph  pk  pl  pn  pr  ps  pt  pw  py  qa  re  ro  rs  ru  rw  sa  sb  sc  sd  se  sg  sh  si  sk  sl  sm  sn  sr  st  su  sv  sy  sz  tc  td  tf  tg  th  tj  tk  tl  tm  tn  to  tr  tt  tv  tw  tz  ua  ug  uk  us  uy  uz  va  vc  ve  vg  vi  vn  vu  wf  ws  ye  za  zm  zw);
	my $found=0;
	@dn=split(/\./,lc($_[0]));
	# search the general top level domain list first
	foreach (@gtld) {
		if (m/$dn[@dn-1]/) {
			my $root_domain=$dn[@dn-2].".".$dn[@dn-1];
			return $root_domain;
			$found++;
		} 
	}
	# search the country code top level domain list secondly
	foreach (@cctld) {
		if (m/$dn[@dn-1]/) {
			my $root_domain=$dn[@dn-3].".".$dn[@dn-2].".".$dn[@dn-1];
                        return $root_domain;
                        $found++;
                } 
        }
	die "$_[0] - this top level domain is unknown: $! \n Please check out your $domain_root \n" if (!$found);
}

sub lookup_whois_server {
  #
  # Select proper whois server based on: a) country code, b) IANA table etc.. 
  # IANA netblock assignment table is copied over from jwhois project under '/etc/jwhois.conf'
  #
	my $ip=$_[0];
	my $ripe="uk,se ";							# List of country codes for ripe whois.ripe.net server lookup
	my $twnic="tw, ";							# List of country codes for whois.twnic.net whois server lookup    				
	# First, guessing the whois server by lookup country code
  	if ($ripe =~ /$_[1]/i) {
		return "RIPE";
	} elsif ($twnic =~ /$_[1]/i) {
		return "TWNIC";
	}       												
	# Secondly, guessing the whois server by lookup IANA assignment table
	my @RIPE_BLKS = qw (129.132.0.0/16 129.177.0.0/16 129.187.0.0/16 130.225.0.0/16 130.226.0.0/15 130.227.0.0/16 130.228.0.0/14 130.232.0.0/13 130.240.0.0/14 130.244.0.0/16 130.244.0.0/16 132.64.0.0/13 132.72.0.0/14 132.76.0.0/15 132.78.0.0/16 137.138.0.0/16 145.0.0.0/8 150.217.0.0/16 151.10.0.0/15 151.100.0.0/16 151.12.0.0/14 151.16.0.0/12 151.3.0.0/16 151.32.0.0/11 151.4.0.0/15 151.64.0.0/11 151.96.0.0/14 158.190.0.0/15 158.192.0.0/14 158.196.0.0/15 159.147.0.0/16 159.148.0.0/15 160.216.0.0/14 160.220.0.0/16 161.110.0.0/15 161.112.0.0/16 163.156.0.0/14 163.160.0.0/12 164.0.0.0/11 164.128.0.0/12 164.32.0.0/13 164.40.0.0/16 168.187.0.0/16 171.16.0.0/12 171.32.0.0/15 192.114.0.0/15 192.116.0.0/15 192.118.0.0/16 192.140.1.0/24 192.140.128.0/17 192.140.16.0/20 192.140.2.0/23 192.140.32.0/19 192.140.4.0/22 192.140.64.0/18 192.140.8.0/21 192.141.0.0/16 192.142.0.0/15 192.144.0.0/16 192.145.0.0/17 192.145.128.0/18 192.145.192.0/19 192.145.224.0/22 192.145.228.0/23 192.145.230.0/24 192.16.192.0/24 192.164.0.0/16 193.0.0.0/8 194.0.0.0/8 195.0.0.0/8 212.0.0.0/8 213.0.0.0/8 217.0.0.0/8 24.132.0.0/16 62.0.0.0/8 80.0.0.0/8 81.0.0.0/8 82.0.0.0/8 83.0.0.0/8 84.0.0.0/8 85.0.0.0/8 86.0.0.0/8 87.0.0.0/8 88.0.0.0/8 89.0.0.0/8 90.0.0.0/8 91.0.0.0/8 43.0.0.0/8); #whois.ripe.net
	# The following NIC Blocks are quoted here for later implementation if necessary
#	my @AFRINIC_BLKS = qw (165.165.0.0/16 195.166.224.0/19 196.0.0.0/8 196.2.128.0/17 196.2.96.0/19 196.200.0.0/13 212.22.160.0/19 213.136.96.0/19 213.154.64.0/19 41.0.0.0/8 62.135.36.0/17 80.87.64.0/19 81.192.0.0/16 81.91.224.0/20 82.101.128.0/18 82.201.128.0/17 82.201.160.0/19 82.201.224.0/19 84.36.0.0/17); # whois.afrinic.net
#	my @APNIC_BLKS = qw (121.0.0.0/8 122.0.0.0/8 123.0.0.0/8 124.0.0.0/8 125.0.0.0/8 126.0.0.0/8 138.130.0.0/16 140.109.0.0/16 140.110.0.0/15 140.112.0.0/12 140.116.0.0/14 140.120.0.0/13 140.128.0.0/13 140.136.0.0/15 140.138.0.0/16 141.223.0.0/16 143.89.0.0/16 143.90.0.0/16 144.130.0.0/15 144.132.0.0/14 144.136.0.0/14 144.140.0.0/16 147.46.0.0/15 150.1.0.0/16 150.100.0.0/15 150.16.0.0/12 150.2.0.0/15 150.32.0.0/11 150.4.0.0/14 150.64.0.0/11 150.8.0.0/13 150.96.0.0/14 155.230.0.0/16 163.13.0.0/16 163.14.0.0/15 163.16.0.0/12 163.32.0.0/16 164.100.0.0/16 164.160.0.0/14 164.164.0.0/16 165.21.0.0/16 165.228.0.0/15 165.76.0.0/16 168.126.0.0/16 168.95.0.0/16 169.208.0.0/16 202.0.0.0/8 203.0.0.0/8 210.0.0.0/8 211.0.0.0/8 218.0.0.0/8 219.0.0.0/8 220.0.0.0/8 221.0.0.0/8 222.0.0.0/8 58.0.0.0/8 59.0.0.0/8 60.0.0.0/8 61.0.0.0/8);  # whois.apnic.net;
#	my @LACNIC_BLKS = qw (189.0.0.0/8 190.0.0.0/8 200.0.0.0/8 201.0.0.0/8 24.232.0.0/16);  # whois.lacnic.net
#	my @JPNIC_BLKS = qw (133.0.0.0/8 150.1.0.0/16 150.100.0.0/16 150.16.0.0/12 150.2.0.0/15 150.32.0.0/11 150.4.0.0/14 150.64.0.0/11 150.8.0.0/13 150.96.0.0/14 158.198.0.0/15 158.200.0.0/13 158.208.0.0/13 158.216.0.0/15 163.130.0.0/15 163.132.0.0/14 163.136.0.0/13 163.144.0.0/14 163.148.0.0/15 192.218.0.0/16 192.244.0.0/16 192.41.192.0/24 192.47.0.0/17 192.47.128.0/18 192.47.142.0/24 192.47.192.0/19 192.47.224.0/20 192.47.240.0/23 192.51.128.0/17 192.51.16.0/20 192.51.32.0/19 192.51.64.0/18 202.11.0.0/16 202.13.0.0/16 202.15.0.0/16 202.16.0.0/14 202.208.0.0/12 202.224.0.0/11 202.23.0.0/16 202.24.0.0/15 202.26.0.0/16 202.32.0.0/14 202.48.0.0/16 203.136.0.0/14 203.140.0.0/15 203.178.0.0/15 203.180.0.0/14 210.128.0.0/11 210.136.0.0/13 210.160.0.0/12 210.188.0.0/14 210.196.0.0/14 210.224.0.0/12 210.248.0.0/13 211.0.0.0/12 211.120.0.0/13 211.128.0.0/13 211.16.0.0/14 219.96.0.0/11 220.104.0.0/13 220.208.0.0/12 221.112.0.0/13 61.112.0.0/12 61.192.0.0/12 61.208.0.0/13);  # whois.nic.ad.jp
#	my @BRNIC_BLKS = qw (200.128.0.0/9 200.17.0.0/16); # whois.nic.br
#	my @KRNIC_BLKS = qw (211.104.0.0/13 211.112.0.0/13 211.172.0.0/14 211.176.0.0/12 211.192.0.0/13 211.52.0.0/14 211.56.0.0/13);	# whois.nic.or.kr
#	my @V6NIC_BLKS = qw (43.0.0.0/8);  # whois.v6nic.net
	$found=Net::CIDR::cidrlookup($ip, @RIPE_BLKS);
	#$found=$cidr->find($ip);
	if ($found) {
		return "RIPE";
	} else {
		# Thirdly, default whois server to ARIN. Need to branch out to other whois server down the road if necessary. 
		return "ARIN"; 
	}
}

sub lookup_netblk_arin () {
  #
  ## Lookup Net block from ARIN whois server by parsing result in arin format. Return the net blocks in a CSV string
  #  
	my $ip=$_[0];
	my $udk=$_[1];
	$ip=~s/^\s+|\s+$//g;
	my $qr= Net::Whois::ARIN->new(
              host    => 'whois.arin.net',
              port    => 43,
              timeout => 30,
          );
	$fnd_cidr=0;								# flag if netblock found in "cidr: x.x.x.x/x" format
	$fnd_net=0;								# flag if netblock found in "net-x-x-x-x-x" format
	$netblk1="";
	@netblk2="";
	my @result= $qr->query($ip);
	# step 1. First round - going thoughh whois result looking for for UDK.  Then determine the netblock formats
	print "\nQuerying whois.arin.net server for $ip. Interesting netblock information is found as below: \n";
	foreach(@result) {
	        my $res=lc;
                # Protection code. Searching for problematic return string. For example, 
	        # to filter out content delivery solution vendor such as Akamai
	        if ($res =~ m/akamai/) {
			return "UNFOUND"; 
		}
		# Printing out information for reference
		if ( ($res =~ m/^orgname\:(.*)$/ ) || ($res =~ m/(.*)net\-\d+\-\d+\-\d+\-\d+(.*)$/) ) {
			print "$res\n";
		}	
		# Use unique domain key (UDK) to differentiate the ISP's netblock
		if ($res =~ m/^orgname\:(.*)$udk(.*)$/ ) {
				$fnd_cidr++;
		}	
		#  netblock in "net-x-x-x-x-x" format
		if ($res =~ m/(.*)$udk(.*)net\-\d+\-\d+\-\d+\-\d+(.*)$/) {
                        	$fnd_net++;
               	}
	}
	# step 2. Second round - match "CIDR: x.x.x.x/x" format 
	if ($fnd_cidr) {
		foreach (@result) {
	        	my $result=lc;
			if ($result =~ m/^cidr/) {
				while ($result=~/(\d+\.\d+\.\d+\.\d+\/\d+)/g) {
					$netblk1=$netblk1.",".$1;
				}
			}
		}
	}
	# Step 3. Third round - for "net-x-x-x-x-x" format, do second (recursive) whois lookup to convert it back to "CIDR: x.x.x.x/x" format 
	if ($fnd_net) {
		foreach (@result) {
	        	my $result=lc;
			if ( ($result =~ m/$_[1]/i) && ($result =~ m/net\-\d+\-\d+-\d+\-\d+/) ) {
				while ($result=~/(net[\-\d+]+)/g) {
					@netblk2=$qr->query($1);
					foreach(@netblk2) {
						my $result2=lc;
						if ( $result2 =~ m/^cidr/) {
							while ($result2=~/(\d+\.\d+\.\d+\.\d+\/\d+)/g) {
								$netblk1=$netblk1.",".$1;
							}
						}
					}
				}
			}
		}
	
	} 
	if($fnd_cidr || $fnd_net) {		
		return $netblk1;
	} else {
		return "UNFOUND";
	}
}

sub lookup_netblk_ripe () {
    #
    ## Lookup Net block from RIPE whois server by parsing result in RIPE format. Return net blocks in a CSV string
    #
	my $ip=$_[0];
	my $UDK=$_[1];
	$ip=~s/^\s+|\s+$//g;
	my $qr= Net::Whois::ARIN->new(
              host    => 'whois.ripe.net',
              port    => 43,
              timeout => 30,
          );
	# RIPE whois lookup conservative mode:
	$conserv=1;		# by default in conservative mode. In case of matching, leave conservative mode domain_id found
	$found=0;		# search for x.x.x.x/xasx netblock format
	$error=0; $netblk="";
	my @result= $qr->query($ip);
	foreach(@result) {
		my $result=lc;   
		# Matching UDK. If no match found, stay in conservative mode
		if (($result =~ m/descr/i) && ($result =~ m/$UDK/i)) {
			$conserv--;
		}
		if ( $result =~ m/\d+\.\d+\.\d+\.\d+\/\d+as/ ) {
			$found++;
                        while ($result=~/(\d+\.\d+\.\d+\.\d+\/\d+)/g) {
					$netblk=$netblk.",".$1;
                        } 
		}
	}
	if(!$found || ($conserv >0)) {
                return "UNFOUND";
	} else {
        	return $netblk;
	}
}

sub lookup_netblk_twnic () {
    #
    ## Lookup Net block from TWNIC whois server
    #  Parsing result in TWNIC format
    #
        my $ip=$_[0];
        $ip=~s/^\s+|\s+$//g;
              my $qr= Net::Whois::ARIN->new(
              host    => 'whois.twnic.net',
              port    => 43,
              timeout => 30,
          );
        my $found=0;
        $error=0;
        $netblk="";
        my @result= $qr->query($ip);
        foreach(@result) {
                my $result=lc;
                # Protection code, flag error in case that twnic whois server return problematic strings
                die "Error. You may query the wrong whois database server:\n whois -h whois.twnic.net $ip\n Error string detected: $result\n Please contact Yang before proceeding further\n" if ( $result =~ m/0\.0\.0\.0/ );
                if ( $result =~ m/\d+\.\d+\.\d+\.\d+\/\d+/ ) {
			$found++;
                        while ($result=~/(\d+\.\d+\.\d+\.\d+\/\d+)/g) {
                                $netblk=$netblk.",".$1;
                        }
                }
        }
        if(!$found) {
                return "UNFOUND";
        } else {
		return $netblk;
	}
}

sub lookup_as_cymru () {
    #
    ## Lookup AS number from cymru whois server
    ## Parsing result in cymru format. The result would be saved to global hash %ASNUM
    #
	my $ip=$_[0];
	$ip=~s/^\s+|\s+$//g;
	my $qr= Net::Whois::ARIN->new(
              host    => 'whois.cymru.com',
              port    => 43,
              timeout => 30,
	);
	my @result= $qr->query($ip);
	my $found=0;
	foreach(@result) {
		chomp;
		if ( m/^\d+(\s+|\t+)\|\s+\d+\.\d+\.\d+\.\d+(\s+|\t+)\|/) {
			$found++;
			@asentr=split(/\|/);
			my $asn=$asentr[0]; $asn=~s/^\s+|\s+$//g;
			my $asname=$asentr[2]; $asname=~s/^\s+|\s+$//g;
			my $pair=$asname."\t|\t".$asn;
			if (!$AS{$pair}) {
				$AS{$pair}=$ip;
			} else {
				$AS{$pair}=$AS{$pair}.",".$ip;		
			} 
		}
	}
	if(!$found) {
		die "Error!!! AS lookup: whois -h whois.cymru.com $ip \n";
		exit (1);
	}
}

sub nessus_2_xls_repository () {
    #
    ## Key component of the easy reporting feature. Perform Nessus to BT EHCOE repository mapping. Matched findings are dumped into a baseline report (currently in MS spreadsheet format).
    ## Un-mapped findings are still directed to an optional output file as business usual
    #
	# Check the optional command switch '-output' and optional field 'non_mapped_nessus_report' in the mapping configuration file for program output. 
	my $file_non_mapped;
	if (defined $opts{output}) {
          $file_non_mapped=$opts{output};
        } else {
          $file_non_mapped=$CNF{non_mapped_nessus_report};
        }
        if (defined $file_non_mapped) { open (OUT_NON_MAPPED, ">", $file_non_mapped) || die "Can't open file: $file_non_mapped : $!\n"; }
	# Read the BT finding template file once; Record/index finding entry positions
	my $parser1 = Spreadsheet::ParseExcel -> new ();
	my $template_book = $parser1->parse($CNF{xls_repository});
	if ( !defined $template_book ) { die $parser1->error(), ". \nError! Please check your mapping.conf for the right xls_repository file path.\n"; 
	} else { 
		$tpl_sheet = $template_book->worksheet($CNF{worksheet});
		if ( !defined $tpl_sheet ) { die $parser1->error(), ".\nError! Please check your mapping.conf for the right worksheet name.\n"; }
	}
	@Mer_Area=index_xls_repository_merged_area();
	our @ENTRS=index_xls_repository_finding_positions();
	index_xls_repository_vid_positions();
	# Read the BT finding template file once again. This time we do the real mapping work!
	my $parser2 = Spreadsheet::ParseExcel::SaveParser->new();
	my $rpt_book = $parser2->Parse($CNF{xls_repository});
	$tpl_sheet_2=$rpt_book->worksheet($CNF{worksheet});
	$rpt_sheet=$rpt_book->AddWorksheet($CNF{rptsheet});
	my $row_pointer=0; my $finding_num=0;
	# Write report header row:
	my $header_cell=$tpl_sheet_2->get_cell(0,0);
	my $header_cell_format  = $header_cell->{FormatNo};
	$rpt_sheet->AddCell($row_pointer, 0, "Finding#", $header_cell_format);
	$rpt_sheet->AddCell($row_pointer, 1, "Issue/Description", $header_cell_format);
	$rpt_sheet->AddCell($row_pointer, 2, "Status", $header_cell_format);
	$rpt_sheet->AddCell($row_pointer, 3, "Recommendation/Fix", $header_cell_format);
	$rpt_sheet->AddCell($row_pointer, 4, "Affected System(s)", $header_cell_format);
	$rpt_sheet->AddCell($row_pointer, 5, "Affected Service(s)", $header_cell_format);
	$rpt_sheet->AddCell($row_pointer, 6, "Nessus Plugin Output", $header_cell_format);
	$rpt_sheet->AddCell($row_pointer, 7, "Nessus Plugin ID", $header_cell_format);
	$row_pointer++;
	# Map nessus findings to xls repository one by one. If mapped, write the entry into new report workbook
	# In case no match found, print out finding to stdout as business usual
	foreach my $pid (sort {$FINDINGS{$b}{level} <=> $FINDINGS{$a}{level}} keys %FINDINGS) {
		unless ($pid) { next; }				# protection code - quick fix of $pid is null exception bug
		my $cve = extract_cve_from_nessus($FINDINGS{$pid}{msg}); 
		my $bid = extract_bid_from_nessus($FINDINGS{$pid}{msg});
		my $osvdb = extract_osvdb_from_nessus($FINDINGS{$pid}{msg});
		my $col_finding_desc=Spreadsheet::ParseExcel::Utility::col2int($CNF{col_finding_desc});
		my $col_status=Spreadsheet::ParseExcel::Utility::col2int($CNF{col_status});
		my $col_recommendation=Spreadsheet::ParseExcel::Utility::col2int($CNF{col_recommendation});
		# Format the contents before use
		my ($SYSTEMS, $SERVICES, $PLUGIN_OUTPUTS);
		foreach (@{$FINDINGS{$pid}{systems}}) { $SYSTEMS= $SYSTEMS.",". $_; }
		foreach (@{$FINDINGS{$pid}{services}}) { $SERVICES = $SERVICES.",".$_; }
		foreach (@{$FINDINGS{$pid}{plugin_outputs}}) { $PLUGIN_OUTPUTS =  $PLUGIN_OUTPUTS . "\n". $_; }	
		$FINDINGS{$pid}{msg} =~ s/(\\n|\\r)+/\t/g;			
		# Ugly codes - a lot of duplication that I can't abstract them (maybe due to broken references to module methods in ParseSaver wrapper). 
		if (search_pid_xls_repository($pid)) {
			$finding_num++;
			$rpt_sheet->AddCell($row_pointer, 0, $finding_num, $header_cell_format);
			my ($r_s, $r_e) = search_pid_xls_repository($pid);
			my $row_start=$row_pointer;
			for (my $j=$r_s; $j<=$r_e; $j++) {				
				my $in_desc_cell=$tpl_sheet_2->get_cell($j,$col_finding_desc);
				my $in_desc_val=$in_desc_cell->value();
				my $cell_desc_format  = $in_desc_cell->{FormatNo};
				$rpt_sheet->AddCell($row_pointer, 1, $in_desc_val, $cell_desc_format);
				my $in_status_cell=$tpl_sheet_2->get_cell($j,$col_status);
				my $in_status_val=$in_status_cell->value();
				my $cell_status_format   = $in_status_cell->{FormatNo};
				$rpt_sheet->AddCell($row_pointer, 2, $in_status_val, $cell_status_format);;
				my $in_recomm_cell=$tpl_sheet_2->get_cell($j,$col_recommendation);
				my $in_recomm_val=$in_recomm_cell->value();
				my $cell_recomm_format   = $in_recomm_cell->{FormatNo};
				$rpt_sheet->AddCell($row_pointer, 3, $in_recomm_val, $cell_recomm_format);
				$row_pointer++;
			}
			$rpt_sheet->AddCell($row_start,4,$SYSTEMS);
			$rpt_sheet->AddCell($row_start,5,$SERVICES);
			$rpt_sheet->AddCell($row_start,6,$PLUGIN_OUTPUTS);
			$rpt_sheet->AddCell($row_start,7,$pid);
			next;
		} elsif (search_cve_xls_repository($cve)) {
			$finding_num++;
			$rpt_sheet->AddCell($row_pointer, 0, $finding_num, $header_cell_format);
			my ($r_s, $r_e) =search_cve_xls_repository($cve);
			my $row_start=$row_pointer;
			for (my $j=$r_s; $j<=$r_e; $j++) {				
				my $in_desc_cell=$tpl_sheet_2->get_cell($j,$col_finding_desc);
				my $in_desc_val=$in_desc_cell->value();
				my $cell_desc_format  = $in_desc_cell->{FormatNo};
				$rpt_sheet->AddCell($row_pointer, 1, $in_desc_val, $cell_desc_format);
				my $in_status_cell=$tpl_sheet_2->get_cell($j,$col_status);
				my $in_status_val=$in_status_cell->value();
				my $cell_status_format   = $in_status_cell->{FormatNo};
				$rpt_sheet->AddCell($row_pointer, 2, $in_status_val, $cell_status_format);;
				my $in_recomm_cell=$tpl_sheet_2->get_cell($j,$col_recommendation);
				my $in_recomm_val=$in_recomm_cell->value();
				my $cell_recomm_format   = $in_recomm_cell->{FormatNo};
				$rpt_sheet->AddCell($row_pointer, 3, $in_recomm_val, $cell_recomm_format);
				$row_pointer++; 
			}
			$rpt_sheet->AddCell($row_start,4,$SYSTEMS);
			$rpt_sheet->AddCell($row_start,5,$SERVICES);
			$rpt_sheet->AddCell($row_start,6,$PLUGIN_OUTPUTS);
			$rpt_sheet->AddCell($row_start,7,$pid);
			next;
		} elsif (search_bid_xls_repository($bid)) {
			$finding_num++;
			$rpt_sheet->AddCell($row_pointer, 0, $finding_num, $header_cell_format);
			my ($r_s, $r_e) =search_bid_xls_repository($bid);
			my $row_start=$row_pointer;
			for (my $j=$r_s; $j<=$r_e; $j++) {				
				my $in_desc_cell=$tpl_sheet_2->get_cell($j,$col_finding_desc);
				my $in_desc_val=$in_desc_cell->value();
				my $cell_desc_format  = $in_desc_cell->{FormatNo};
				$rpt_sheet->AddCell($row_pointer, 1, $in_desc_val, $cell_desc_format);
				my $in_status_cell=$tpl_sheet_2->get_cell($j,$col_status);
				my $in_status_val=$in_status_cell->value();
				my $cell_status_format   = $in_status_cell->{FormatNo};
				$rpt_sheet->AddCell($row_pointer, 2, $in_status_val, $cell_status_format);;
				my $in_recomm_cell=$tpl_sheet_2->get_cell($j,$col_recommendation);
				my $in_recomm_val=$in_recomm_cell->value();
				my $cell_recomm_format   = $in_recomm_cell->{FormatNo};
				$rpt_sheet->AddCell($row_pointer, 3, $in_recomm_val, $cell_recomm_format);
				$row_pointer++;
			}
			$rpt_sheet->AddCell($row_start,4,$SYSTEMS);
			$rpt_sheet->AddCell($row_start,5,$SERVICES);
			$rpt_sheet->AddCell($row_start,6,$PLUGIN_OUTPUTS);
			$rpt_sheet->AddCell($row_start,7,$pid);
			next;
		} elsif (search_osvdb_xls_repository($osvdb)) {
			$finding_num++;
			$rpt_sheet->AddCell($row_pointer, 0, $finding_num, $header_cell_format);
			my ($r_s, $r_e) = search_osvdb_xls_repository($osvdb);
			my $row_start=$row_pointer;
			for (my $j=$r_s; $j<=$r_e; $j++) {				
				my $in_desc_cell=$tpl_sheet_2->get_cell($j,$col_finding_desc);
				my $in_desc_val=$in_desc_cell->value();
				my $cell_desc_format  = $in_desc_cell->{FormatNo};
				$rpt_sheet->AddCell($row_pointer, 1, $in_desc_val, $cell_desc_format);
				my $in_status_cell=$tpl_sheet_2->get_cell($j,$col_status);
				my $in_status_val=$in_status_cell->value();
				my $cell_status_format   = $in_status_cell->{FormatNo};
				$rpt_sheet->AddCell($row_pointer, 2, $in_status_val, $cell_status_format);;
				my $in_recomm_cell=$tpl_sheet_2->get_cell($j,$col_recommendation);
				my $in_recomm_val=$in_recomm_cell->value();
				my $cell_recomm_format   = $in_recomm_cell->{FormatNo};
				$rpt_sheet->AddCell($row_pointer, 3, $in_recomm_val, $cell_recomm_format);
				$row_pointer++;
			}
			$rpt_sheet->AddCell($row_start,4,$SYSTEMS);
			$rpt_sheet->AddCell($row_start,5,$SERVICES);
			$rpt_sheet->AddCell($row_start,6,$PLUGIN_OUTPUTS);
			$rpt_sheet->AddCell($row_start,7,$pid);
			next;
		} else {					# Business usual - unmapped findings are still piped to either a output file or stdout
			# Format contents before printing out
			$FINDINGS{$pid}{systems}=~s/,/\n/g;
			$FINDINGS{$pid}{services}=~s/,/\n/g;
			if (defined $file_non_mapped)  {
				if ($verbose) { print "Saving non-mapped Nessus findings into file: $file_non_mapped ...\n"; }
				print OUT_NON_MAPPED "\n\nNessus Plugin ID: $pid\n";
				print OUT_NON_MAPPED "Risk Level: ";
				if ($FINDINGS{$pid}{level} > 2) {
					print OUT_NON_MAPPED "High\n";
				} elsif ($FINDINGS{$pid}{level} >0) {
					print OUT_NON_MAPPED "Medium\n";
				} else {
					print OUT_NON_MAPPED "Low\n";
				}
				print OUT_NON_MAPPED "Affected System(s): \n";
				foreach (@{$FINDINGS{$pid}{systems}}) { print OUT "$_\n"; }
				print OUT_NON_MAPPED "Affected Service(s): \n";
				foreach (@{$FINDINGS{$pid}{services}}) { print OUT "$_\n"; }
				print OUT_NON_MAPPED "Vulnerability Details: \n\t$FINDINGS{$pid}{msg}\n";
			} else {
				print "\n\nNessus Plugin ID: $pid\n";
				print "Risk Level: ";
				if ($FINDINGS{$pid}{level} > 2) {
					print "High\n";
				} elsif ($FINDINGS{$pid}{level} >0) {
					print "Medium\n";
				} else {
					print "Low\n";
				}
				print "Affected System(s): \n";
				foreach (@{$FINDINGS{$pid}{systems}}) { print "$_\n"; }
				print "Affected Service(s): \n";
				foreach (@{$FINDINGS{$pid}{services}}) { print "$_\n"; }
				print "Vulnerability Details: \n\t$FINDINGS{$pid}{msg}\n";
			}
		}
	}
	$rpt_book->{Worksheet}[0] = $rpt_book->{Worksheet}[1];			# Delete template sheet
	$rpt_book->{_SheetNo}--; $rpt_book->{SheetCount}--; 			# clean-up
	my $xls_rpt=$rpt_book->SaveAs($CNF{xls_report});			# Save report
	my $wksheet = $xls_rpt->sheets($CNF{rptsheet});				# Reset report column width for readability
	$wksheet->set_column( 'B:B', 35 );
	$wksheet->set_column( 'D:D', 25 );
	$wksheet->set_column( 'E:E', 20 );
	$wksheet->set_column( 'F:F', 20 );
	$wksheet->set_column( 'G:G', 30 );
	$wksheet->set_column( 'H:H', 20 );
	print "Done saving to the BT EHCOE baseline report:\t$CNF{xls_report}\n";
	if (defined $file_non_mapped) {
		close (OUT_NON_MAPPED);
		print "Done saving the un-mapped Nessus findings into report:\t$file_non_mapped\n";
	}
	undef $parser1;
	undef $parser2;
}

sub index_xls_repository_merged_area () {
#
## Find and index merge area info. This info will be used to scope the finding entries
#   
	# Sort and index merged areas
	my $MA=$tpl_sheet->get_merged_areas();
	if (ref($MA) eq 'ARRAY') {
		@MA2=@$MA;
	} else {
		#Trouble-shooting code in case of program failure
		print Dumper $MA;
	}
	return @MA2;
}

sub extract_cve_from_nessus {
    #
    ## Extract CVE IDs from the Nessus message body into an array for later use. Return the array reference.
    #
	my @cve;
	my $msg=$_[0];
	$msg=~s/(\r|\n)/\s/g;
	if ($msg =~ /(CVE\-\d+\-\d+)/gi) {
		if ($verbose) { print "Found CVE from Nessus message boday: $_\n"; }
		push(@cve,$1);		
	}
	return \@cve;
}

sub extract_bid_from_nessus {
    #
    ## Extract BIDs from the Nessus message body into an array for later use. Return the array reference.
    #
	my @bid;
	if ($_[0] =~ m/(BID : (.)+Other references)/) {
		my $string=$1;
		$string=~s/(\s)//g;
		my @B=split(/:/,$string);
		my @C=split(/\n/,$B[1]);
		my @I=split(/,/,$C[0]);
		foreach(@I) {
			if (/(\d+)/) {
				push(@bid,$1);
			}
		}		
	}
	return \@bid;
}

sub extract_osvdb_from_nessus {
    #
    ## Extract OSVDB number from the Nessus message body into an array for later use. Return the array reference.
    #
	my @osvdb;
	my $msg=$_[0];
	$msg=~s/(\r|\n)/\s/g;
	while ($msg =~ /(OSVDB:\s*\d+)/gi) {
		my @OSV=split(/:/,$1);
		my $id=$osv[1];
		$id =~ s/\s+//g;
		push (@osvdb,$id);
	}
	return \@osvdb;
}

sub index_xls_repository_finding_positions () {
#
## Sort through merged area data to identify row range for each finding. Return the row range [row_start, row_end] position 
## The recognition algorithm is based on the fact, that column A is a merged cell in the template sheet
#
	# starting at column A (col_finding_num) of the template
	my @ROW_RANGE;
	foreach (@Mer_Area) { 
		if (@$_) {
			my ($row_start, $col_start, $row_end, $col_end) = @$_;
			my $col_finding_num=Spreadsheet::ParseExcel::Utility::col2int($CNF{col_finding_num});
			if (($col_start eq $col_finding_num) && ($col_end eq $col_finding_num)) {
				@A=[$row_start,$row_end];
				push (@ROW_RANGE, @A);
			}
				
		}
	}
	return @ROW_RANGE;
}

sub index_xls_repository_vid_positions () {
#
## Sort through the repository and index the position of all vulnerability IDs' (CVE,OSVDB,BID,Nessuss-ID) positions in one shot 
## Save the informatin into hash table %DBVIDS for later use
#
	my $found=0;
	my $col_finding_desc=Spreadsheet::ParseExcel::Utility::col2int($CNF{col_finding_desc});
	my ($r_min,$r_max) = $tpl_sheet->row_range();
	for (my $i=0; $i<$r_max; $i++) {
		my $cell = $tpl_sheet->get_cell($i,$col_finding_desc); 
		if ($cell) {
			my $val_c = $cell->value(); 
			if ($val_c =~ /CVE\-\d+\-\d+/i) {				# Index tagged CVE ID from repository
				my @entry=locate_finding_position_xls_repository($i);
				while ( $val_c =~ /(CVE\-\d+\-\d+)/gi) {
					my $cid=$1;	
					if ($verbose) { print "Index tagged CVE ID within repository into DBVIDS: $1\n";}
					$DBVIDS{CVE}{$cid}=\@entry;
				}
			} 
			if ($val_c =~ /(BID:\s*\d+)/i) {				# Index tagged BID from repository
				my @entry=locate_finding_position_xls_repository($i);
				while ($val_c =~ /(BID:\s*\d+)/gi) {
					my $bid;
					if ( $1 =~ /(\d+)/ ) {
						$bid=$1;					
						if ($verbose) { print "Index tagged BID within repository into DBVIDS: $1\n";}
						$DBVIDS{BID}{$bid}=\@entry;
					}
				}
			} 
			if ($val_c =~ /(OSVDB\:*\s*\d+)/i) {				# Index tagged OSVDD from repository
				my @entry=locate_finding_position_xls_repository($i);
				while ($val_c =~ /(OSVDB\:*\s*\d+)/gi) {
					my $oid;
					if ($1 =~ /(\d+)/) {
						$oid=$1;
						if ($verbose) { print "Index tagged OSVDB ID within repository into DBVIDS: $1\n";}
						$DBVIDS{OSVDB}{$oid}=\@entry;
					}
				}
			} 
			if ($val_c =~ /(Nessus-ID-\d+)/i) {				# Index tagged Nessus ID from repository
				my @entry=locate_finding_position_xls_repository($i);
				while ($val_c =~ /(Nessus-ID-\d+)/gi) {
					my $pid;
					if ($1 =~ /(\d+)/) {
						$pid=$1;
						if ($verbose) { print "Index tagged Nessus-ID within repository into DBVIDS: $1\n";}
						$DBVIDS{NESSUS}{$pid}=\@entry;
					}
				}		
			}
		}

	}
}

sub search_pid_xls_repository () {
    #
    ## Perform Nessus to xls repository mapping by using Nessus plugin-id. This is accomplished by searching
    ## the hash table %DBVIDS for associated Nessus ID. Finding entry location is returned if mapped.
    #
	if ($verbose) { print "Perform DB search against \%DBVIDS by using Nessus ID: $_[0]\n"; }
        my $found=0;
	my $pid=$_[0];
	if ($pid && $DBVIDS{NESSUS}{$pid}) {
		$found++;
		if ($verbose) { print "Found Nessus ID match within the DBVID: $pid\n"; }
		if ($verbose) { print "Nessus ID $pid position within repository: @{$DBVIDS{NESSUS}{$pid}}\n";  }
		return @{$DBVIDS{NESSUS}{$pid}};
	}
	return $found;
}

sub search_cve_xls_repository () {
    #
    ## Perform Nessus to xls repository mapping by using CVE ID. This is accomplished by searching
    ## hash table %DBVIDS for associated CVEs
    #
	if ($verbose) { print "Perform DB search against \%DBVIDS by using CVE: @{$_[0]}\n"; }
        my $found=0;
	foreach ( @{$_[0]} ) {
		my $cve=$_;
		if ($cve && $DBVIDS{CVE}{$cve}) {
			$found++;
			if ($verbose) { print "Found CVE match within the DBVID: $cve\n";}
			if ($verbose) { print "$cve position within repository: @{$DBVIDS{CVE}{$cve}}\n"; } 
			return @{$DBVIDS{CVE}{$cve}};
		}
	}
	return $found;
}

sub search_bid_xls_repository () {
    #
    ## Perform Nessus to xls repository mapping by using BID ID. This is accomplished by searching
    ## hash %DBVIDS table for associated BIDs
    #
	if ($verbose) { print "Perform DB search against \%DBVIDS by using BID: @{$_[0]}\n"; }
	my $found=0;
	foreach ( @{$_[0]} ) {
		my $bid=$_; 
		if ($bid && $DBVIDS{BID}{$bid}) {
			$found++;
			if ($verbose) { print "Found BID match within the DBVID: $bid\n";}
			if ($verbose) { print "BID $bid position within repository: @{$DBVIDS{BID}{$bid}}\n";  }
			return @{$DBVIDS{BID}{$bid}};
		}
	}
	return $found;
}

sub search_osvdb_xls_repository () {
    #
    ## Perform Nessus to xls repository mapping by using OSVDB ID. This is accomplished by searching
    ## hash %DBVIDS table for associated OSVDBs
    #
	if ($verbose) { print "Perform DB search against \%DBVIDS by using OSVDB ID: @{$_[0]}\n"; }
	my $found=0;
	foreach ( @{$_[0]} ) {
		my $oid=$_; 
		if ($oid && $DBVIDS{OSVDB}{$oid}) {
			$found++;
			if ($verbose) { print "Found OSVDB match within the DBVID: $oid\n";}
			if ($verbose) { print "OSVDB ID $oid position within repository: @{$DBVIDS{OSVDB}{$oid}}\n";  }
			return @{$DBVIDS{OSVDB}{$oid}};
		}
	}
	return $found;
}

sub locate_finding_position_xls_repository () {
    #
    ## Locate finding entry position in the form of "row range" (row_start, row_end) within the xls repository, and return the position as an array if found.
    #
	my $found=0; my @entry; 
	foreach (@ENTRS) {
		my ($s, $e)=@$_;
		if ( ($s <= $_[0]) && ($_[0] <= $e) ) {
			$found++;
			@entry=($s,$e);
			return @entry;
		}
	}
	return $found;
}

sub index_xml_repository () {
#
## Sort through the xml repository and index all vulnerability IDs (CVE,OSVDB,BID,Nessuss-ID) in one shot
## Save the information into hash table %DBXML for later use
#
	my $size_file = -s $CNF{xml_repository};
	print "Load BT EHCOE XML repository: $CNF{xml_repository}\nFile size: $size_file bytes\n";
	my $parser=XML::LibXML->new();
	my $doc= $parser->parse_file ($CNF{xml_repository});
	#EHCOE xml repository XML DOM tree structure: "Records" => "Record" => "Field"
	foreach my $records ($doc->getElementsByTagName("Records")) {	
		foreach my $record ($records->getElementsByTagName("Record")){	
			my %REC;
			foreach my $field ($record->getChildNodes()) {
				my $xmlstring = $field->toString();
				chomp($xmlstring);
				if ($xmlstring ne "") {
					my ($key,$value);
					my @FIELD=split(/\<Field name\=/,$xmlstring);
					($key,$value)=split(/\s*value\=/,$FIELD[1]);
					$key=~s/\"//g;
					$value=~s/\"//g;
					$value=~s/\/\>.*//;
					$REC{$key}=$value;
				}
			}
			if (defined $REC{'NessusID'}) { 				# Index tagged Nessus ID from repository
				my $pid=$REC{'NessusID'};
				$pid=~s/(\t|\s)*//g;
				my @PIDS=split(/,/,$pid);
				foreach (@PIDS) {
					if (/\d+/) {
						my $id=$_;
						if ($verbose) { print "Index tagged Nessus-ID within repository into DBXML: $id\n";}
						$DBXML{NESSUS}{$id}{Title}=$REC{'Vulnerability Title'};
						$DBXML{NESSUS}{$id}{Difficulty}=$REC{'Difficulty'};
						$DBXML{NESSUS}{$id}{Description}=$REC{'Description'};
						$DBXML{NESSUS}{$id}{Recommendation}=$REC{'Recommendation'};
						$DBXML{NESSUS}{$id}{BTVID}=$REC{'BT Ref #'};
					}
				}
			}
			if ($REC{'Description'} =~ /CVE\-\d+\-\d+/i) {			# Index tagged CVE ID from repository
				while ( $REC{'Description'} =~ /(CVE\-\d+\-\d+)/gi) {
					my $cid=$1;	
					if ($verbose) { print "Index tagged CVE ID within repository into DBXML: $1\n";}
					$DBXML{CVE}{$cid}{Title}=$REC{'Vulnerability Title'};
					$DBXML{CVE}{$cid}{Difficulty}=$REC{'Difficulty'};
					$DBXML{CVE}{$cid}{Description}=$REC{'Description'};
					$DBXML{CVE}{$cid}{Recommendation}=$REC{'Recommendation'};
					$DBXML{CVE}{$cid}{BTVID}=$REC{'BT Ref #'};
				}
			} 
			if ($REC{'Description'} =~ /(BID:\s*\d+)/i) {			# Index tagged BID from repository
				while ($REC{'Description'} =~ /(BID:\s*\d+)/gi) {
					my $bid;
					if ( $1 =~ /(\d+)/ ) {
						$bid=$1;					
						if ($verbose) { print "Index tagged BID within repository into DBXML: $1\n";}
						$DBXML{BID}{$bid}{Title}=$REC{'Vulnerability Title'};
						$DBXML{BID}{$bid}{Difficulty}=$REC{'Difficulty'};
						$DBXML{BID}{$bid}{Description}=$REC{'Description'};
						$DBXML{BID}{$bid}{Recommendation}=$REC{'Recommendation'};
						$DBXML{BID}{$bid}{BTVID}=$REC{'BT Ref #'};
					}
				}
			} 
			if ($REC{'Description'} =~ /(OSVDB\:*\s*\d+)/i) {		# Index tagged OSVDD from repository
				while ($REC{'Description'} =~ /(OSVDB\:*\s*\d+)/gi) {
					my $oid;
					if ($1 =~ /(\d+)/) {
						$oid=$1;
						if ($verbose) { print "Index tagged OSVDB ID within repository into DBXML: $1\n";}
						$DBXML{OSVDB}{$oid}{Title}=$REC{'Vulnerability Title'};
						$DBXML{OSVDB}{$oid}{Difficulty}=$REC{'Difficulty'};
						$DBXML{OSVDB}{$oid}{Description}=$REC{'Description'};
						$DBXML{OSVDB}{$oid}{Recommendation}=$REC{'Recommendation'};
						$DBXML{OSVDB}{$oid}{BTVID}=$REC{'BT Ref #'};
					}
				}
			} 
		}

	}
	undef $parser;
	print "Done loading BT EHCOE XML repository $CNF{xml_repository}\n\n";
}

sub nessus_2_xml_repository () {
    #
    ## Key component of the easy reporting feature. Perform Nessus to BT EHCOE repository mapping. Mapped findings are dumped into a baseline report (in HTML format).
    ## Un-mapped findings are still directed to an optional output file as business usual
    #
	print "Search the repository for known Nessus finding write-ups ...\n";
	# Check the optional command switch '-output' and optional field 'non_mapped_nessus_report' in the configuration file for program output. 
	my $file_non_mapped;
	if (defined $opts{output}) {
		$file_non_mapped=$opts{output}."_non_mapped_nessus.txt";
	} elsif (defined $CNF{non_mapped_nessus_report_html}) {
		$file_non_mapped=$CNF{non_mapped_nessus_report_html};
        } 
	if (defined $file_non_mapped) { 
		open (OUT_NON_MAPPED, ">", $file_non_mapped) || die "Can't open file: $file_non_mapped : $!\n"; 
	}
	# Map Nessus findings to xml repository one by one. If mapped, save the entry into global index %BTFINDINGS 
	# In case no match found, print out finding to stdout as business usual
	foreach my $pid (sort {$FINDINGS{$b}{level} <=> $FINDINGS{$a}{level}} keys %FINDINGS) {
		unless ($pid) { next; }				
		my $cve = extract_cve_from_nessus($FINDINGS{$pid}{msg}); 
		my $bid = extract_bid_from_nessus($FINDINGS{$pid}{msg});
		my $osvdb = extract_osvdb_from_nessus($FINDINGS{$pid}{msg});
		foreach (@{$FINDINGS{$pid}{plugin_outputs}}) { 
			$PLUGIN_OUTPUTS =  $PLUGIN_OUTPUTS . "\n". $_; 
		}	
		$FINDINGS{$pid}{msg} =~ s/(\\n|\\r)+/\t/g;
		# Search the index for the vulnerability ids, and add it to report if found. Otherwise pipe out to stdout if not found as business usual 
		if ($DBXML{NESSUS}{$pid}) {		# start with Nessus ID mapping
			my $title = $DBXML{NESSUS}{$pid}{Title};
			my $risk_score = bt_risk_score_lookup($title);
			my $id_string = decode_entities($DBXML{NESSUS}{$pid}{BTVID});
			my $btid;			
			if ( $id_string =~ /(\d+)/ ) {
				$btid = $1;
			} else {
				die "Error! Invalid BT Ref # field value in the $CNF{xml_repository} file: entry $DBXML{NESSUS}{$pid}{Title} : $id_string does not contain a valid integer as the ID\n";
			}
			if ($BTFINDINGS{$btid}{pids}) {
				$BTFINDINGS{$btid}{pids} = $BTFINDINGS{$btid}{pids}.",".$pid;
			} else {
				$BTFINDINGS{$btid}{type}=NESSUS;
				$BTFINDINGS{$btid}{vid}=$pid;
				$BTFINDINGS{$btid}{pids}=$pid;
				$BTFINDINGS{$btid}{score}=$risk_score;				
			}
			#print "Found Neesus ID in the repository: $pid, BT ID: $btid\n";
			next;
		} elsif (search_vid_xml_repository($cve,CVE)) {
			my $id=search_vid_xml_repository($cve,CVE);
			my $title = $DBXML{CVE}{$id}{Title};
			my $risk_score = bt_risk_score_lookup($title);
			my $id_string = decode_entities($DBXML{CVE}{$id}{BTVID});
			my $btid;
			if ( $id_string =~ /(\d+)/ ) {
				$btid = $1;
			} else {
				die "Error! Invalid BT Ref # field value in the $CNF{xml_repository} file: entry $DBXML{CVE}{$id}{Title} : $id_string does not contain a valid integer as the ID\n";
			}
			if ($BTFINDINGS{$btid}{pids}) {
				$BTFINDINGS{$btid}{pids} = $BTFINDINGS{$btid}{pids}.",".$pid;
			} else {
				$BTFINDINGS{$btid}{type}=CVE;
				$BTFINDINGS{$btid}{vid}=$id;
				$BTFINDINGS{$btid}{pids}=$pid;
				$BTFINDINGS{$btid}{score}=$risk_score;
			}
			next;
		} elsif (search_vid_xml_repository($bid,BID)) {
			my $id=search_vid_xml_repository($bid,BID);
			my $title = $DBXML{BID}{$id}{Title};
			my $risk_score = bt_risk_score_lookup($title);
			my $id_string = decode_entities($DBXML{BID}{$id}{BTVID});
			my $btid;
			if ( $id_string =~ /(\d+)/ ) {
				$btid = $1;
			} else {
				die "Error! Invalid BT Ref # field value in the $CNF{xml_repository} file: entry $DBXML{BID}{$id}{Title} : $id_string does not contain a valid integer as the ID\n";
			}
			if ($BTFINDINGS{$btid}{pids}) {
				$BTFINDINGS{$btid}{pids} = $BTFINDINGS{$btid}{pids}.",".$pid;
			} else {
				$BTFINDINGS{$btid}{type}=BID;
				$BTFINDINGS{$btid}{vid}=$id;
				$BTFINDINGS{$btid}{pids}=$pid;
				$BTFINDINGS{$btid}{score}=$risk_score;
			}
			next;
		} elsif (search_vid_xml_repository($osvdb,OSVDB)) {
			my $id=search_vid_xml_repository($osvdb,OSVDB);
			my $title = $DBXML{OSVDB}{$id}{Title};
			my $risk_score = bt_risk_score_lookup($title);
			my $id_string = decode_entities($DBXML{OSVDB}{$id}{BTVID});
			my $btid;
			if ( $id_string =~ /(\d+)/ ) {
				$btid = $1;
			} else {
				die "Error! Invalid BT Ref # field value in the $CNF{xml_repository} file: entry $DBXML{OSVDB}{$id}{Title} : $id_string does not contain a valid integer as the ID\n";
			}
			if ($BTFINDINGS{$btid}{pids}) {
				$BTFINDINGS{$btid}{pids} = $BTFINDINGS{$btid}{pids}.",".$pid;
			} else {
				$BTFINDINGS{$btid}{type}=OSVDB;
				$BTFINDINGS{$btid}{vid}=$id;
				$BTFINDINGS{$btid}{pids}=$pid;
				$BTFINDINGS{$btid}{score}=$risk_score;
			}
			next;
		} else {					# Business usual - unmapped findings are still piped to either a output file or stdout
			# Format contents before printing out
			$FINDINGS{$pid}{systems}=~s/,/\n/g;
			$FINDINGS{$pid}{services}=~s/,/\n/g;
			if (defined $file_non_mapped)  {
				if ($verbose) { print "Saving non-mapped Nessus findings into file: $file_non_mapped ...\n"; }
				print OUT_NON_MAPPED "\n\nNessus Plugin ID: $pid\n";
				print OUT_NON_MAPPED "Risk Level: ";
				if ($FINDINGS{$pid}{level} > 2) {
					print OUT_NON_MAPPED "High\n";
				} elsif ($FINDINGS{$pid}{level} >0) {
					print OUT_NON_MAPPED "Medium\n";
				} else {
					print OUT_NON_MAPPED "Low\n";
				}
				print OUT_NON_MAPPED "Affected System(s): \n";
				foreach (@{$FINDINGS{$pid}{systems}}) { print OUT_NON_MAPPED "$_\n"; }
				print OUT_NON_MAPPED "Affected Service(s): \n";
				foreach (@{$FINDINGS{$pid}{services}}) { print OUT_NON_MAPPED "$_\n"; }
				print OUT_NON_MAPPED "Vulnerability Details: \n\t$FINDINGS{$pid}{msg}\n";
			} else {
				print "\n\nNessus Plugin ID: $pid\n";
				print "Risk Level: ";
				if ($FINDINGS{$pid}{level} > 2) {
					print "High\n";
				} elsif ($FINDINGS{$pid}{level} >0) {
					print "Medium\n";
				} else {
					print "Low\n";
				}
				print "Affected System(s): \n";
				foreach (@{$FINDINGS{$pid}{systems}}) { print "$_\n"; }
				print "Affected Service(s): \n";
				foreach (@{$FINDINGS{$pid}{services}}) { print "$_\n"; }
				print "Vulnerability Details: \n\t$FINDINGS{$pid}{msg}\n";
			}
		}

	}
	if (defined $file_non_mapped) {
		close(OUT_NON_MAPPED);
		print "Save the rest Nessus findings into report: $file_non_mapped ... Done!\n";
	}
	print_html_finding_report();
}

sub bt_risk_score_lookup () {
    #
    ## Perform BT risk score lookup on the BT finding title, return a risk score for later report sorting purpose
    ## BT Risk score Chart: 5-High, 4-Medium, 3-Low, 2-Note, 1-unknown
    #
	my $title=decode_entities($_[0]);
	my $score;
	if ($title =~ /\(.*High.*\)/i) {
		$score=5;
	} elsif ($title =~ /\(.*Medium.*\)/i) {
		$score=4;
	} elsif ($title =~ /\(.*Low.*\)/i) {
		$score=3;
	} elsif ($title =~ /\(.*Note.*\)/i) {
		$score=2;
	} else {
		$score=1;
	}
	return $score;
}

sub search_vid_xml_repository () {
    #
    ## Perform Nessus to xml repository mapping by using Vulnerability ID (VID) such as CVE,OSVDB,BID. This is accomplished by searching
    ## hash table %DBXML for associated VIDs. Return VID ID if found, or 0 otherwise.
    #
	if ($verbose) { print "Perform DB search against \%DBXML by using $_[1]: @{$_[0]}\n"; }
        my $found=0;
	foreach ( @{$_[0]} ) {
		my $vid=$_;
		if ($vid && $DBXML{$_[1]}{$vid}) {
			if ($verbose) { print "Found $_[1] match within DBXML: $vid\n";}
			return $vid;
		}
	}
	return $found;
}

sub print_html_finding_report () {
    #
    ## Print out the HTML finding report
    #
	my $file_mapped;
	if (defined $opts{output}) { 
		$file_mapped = $opts{output}."_EHCOE_RPT.html";
		open (OUT_MAPPED, ">", $file_mapped) || die "Can't open file: $file_mapped : $!\n"; 
	} elsif (defined $CNF{html_report}) { 
		$file_mapped = $CNF{html_report};
		open (OUT_MAPPED, ">", $file_mapped) || die "Can't open file: $file_mapped : $!\n"; 
	} else {
		die "Error! Mapped EHCOE report file is not defined. Please define html_report field in the mapping configuration file $mapping. Or using -o switch of the program.\n";
	}	
	# Write the html report header here
	print OUT_MAPPED <<HEADER_RPT;
<HTML>
<Title>BT EHCOE Baseline Report</Title>
<Body>
<P style="MARGIN: 12pt 0in 6pt"><STRONG>BT EHCOE Vulnerability Assessment Baseline Report</STRONG></P>
<font size="2">- Generated by Maverick Program's Easy Reporting Engine. <br>
- Contact the programmer Yang Li at (917) 667-1972 for any question.  <BR><BR><BR>
</font>
<TABLE style="BORDER-RIGHT: medium none; BORDER-TOP: medium none; MARGIN: auto auto auto 5.4pt; BORDER-LEFT: medium none; BORDER-BOTTOM: medium none; 
BORDER-COLLAPSE: collapse" cellSpacing=0 cellPadding=0 width=855 border=1>
    <THEAD>
        <TR>
            <TD style="BORDER-RIGHT: navy 1pt solid; PADDING-RIGHT: 5.4pt; BORDER-TOP: navy 1pt solid; PADDING-LEFT: 5.4pt; BACKGROUND: 3399FF; PADDING-BOTTOM: 0in; BORDER-LEFT: navy 1pt solid; WIDTH: 27pt; PADDING-TOP: 0in; BORDER-BOTTOM: navy 1pt solid" vAlign=top width=36>
            <P style="MARGIN: 2pt 0in 0pt"><STRONG>#</STRONG></P>
            </TD>
            <TD style="BORDER-RIGHT: navy 1pt solid; PADDING-RIGHT: 5.4pt; BORDER-TOP: navy 1pt solid; PADDING-LEFT: 5.4pt; BACKGROUND: 3399FF; PADDING-BOTTOM: 0in; BORDER-LEFT: #ece9d8; WIDTH: 300.95pt; PADDING-TOP: 0in; BORDER-BOTTOM: navy 1pt solid" vAlign=top width=384>
            <P style="MARGIN: 2pt 0in 0pt"><STRONG>Issue/Description</STRONG></P>
            </TD>
            <TD style="BORDER-RIGHT: navy 1pt solid; PADDING-RIGHT: 5.4pt; BORDER-TOP: navy 1pt solid; PADDING-LEFT: 5.4pt; BACKGROUND: 3399FF; PADDING-BOTTOM: 0in; BORDER-LEFT: #ece9d8; WIDTH: 41.95pt; PADDING-TOP: 0in; BORDER-BOTTOM: navy 1pt solid" vAlign=top width=56>
            <P style="MARGIN: 2pt 0in 0pt"><STRONG>Status</STRONG></P>
            </TD>
            <TD style="BORDER-RIGHT: navy 1pt solid; PADDING-RIGHT: 5.4pt; BORDER-TOP: navy 1pt solid; PADDING-LEFT: 5.4pt; BACKGROUND: 3399FF; PADDING-BOTTOM: 0in; BORDER-LEFT: #ece9d8; WIDTH: 300.95pt; PADDING-TOP: 0in; BORDER-BOTTOM: navy 1pt solid" vAlign=top width=384>
            <P style="MARGIN: 2pt 0in 0pt"><STRONG>Recommendation/Fix</STRONG></P>
            </TD>
            <TD style="BORDER-RIGHT: navy 1pt solid; PADDING-RIGHT: 5.4pt; BORDER-TOP: navy 1pt solid; PADDING-LEFT: 5.4pt; BACKGROUND: 3399FF; PADDING-BOTTOM: 0in; BORDER-LEFT: #ece9d8; WIDTH: 90pt; PADDING-TOP: 0in; BORDER-BOTTOM: navy 1pt solid" vAlign=top width=86>
            <P style="MARGIN: 2pt 0in 0pt"><STRONG>Test ID</STRONG></P>
            </TD>
            <TD style="BORDER-RIGHT: navy 1pt solid; PADDING-RIGHT: 5.4pt; BORDER-TOP: navy 1pt solid; PADDING-LEFT: 5.4pt; BACKGROUND: 3399FF; PADDING-BOTTOM: 0in; BORDER-LEFT: #ece9d8; WIDTH: 250pt; PADDING-TOP: 0in; BORDER-BOTTOM: navy 1pt solid" vAlign=top width=250>
            <P style="MARGIN: 2pt 0in 0pt"><STRONG>Test Evidence</STRONG></P>
            </TD>
        </TR>
HEADER_RPT
	# print out high risk finding section
	my $finding_num=0;
	my $finding_label;
	print OUT_MAPPED <<HEADER_SECTION_HIGH;
    <TBODY>
        <TR>
            <TD style="BORDER-RIGHT: #ece9d8; PADDING-RIGHT: 5.4pt; BORDER-TOP: #ece9d8; PADDING-LEFT: 5.4pt; BACKGROUND: red; PADDING-BOTTOM: 0in; BORDER-LEFT: navy 1pt solid; WIDTH: 27pt; PADDING-TOP: 0in; BORDER-BOTTOM: navy 1pt solid" vAlign=top width=36>
            <P style="MARGIN: 2pt 0in 0pt"><STRONG>&nbsp;</STRONG></P>
            </TD>
            <TD style="BORDER-RIGHT: navy 1pt solid; PADDING-RIGHT: 5.4pt; BORDER-TOP: #ece9d8; PADDING-LEFT: 5.4pt; BACKGROUND: red; PADDING-BOTTOM: 0in; BORDER-LEFT: #ece9d8; WIDTH: 613.9pt; PADDING-TOP: 0in; BORDER-BOTTOM: navy 1pt solid" width=819 colSpan=5>
            <P style="MARGIN: 2pt 0in 0pt"><SPAN><STRONG>High-Risk Issues</STRONG></SPAN></P>
            </TD>
        </TR>
    </TBODY>
HEADER_SECTION_HIGH
	foreach my $btid (keys %BTFINDINGS) {
		unless ($btid) { next; }	
		if  ($BTFINDINGS{$btid}{score} == 5) {
			$finding_num++;
			$finding_label="H".$finding_num."\.";
			print_html_report_row ($btid,$finding_label);
		}
	}
	# print out medium risk finding section
	$finding_num=0;
	print OUT_MAPPED <<HEADER_SECTION_MED;
    <TBODY>
        <TR>
            <TD style="BORDER-RIGHT: #ece9d8; PADDING-RIGHT: 5.4pt; BORDER-TOP: #ece9d8; PADDING-LEFT: 5.4pt; BACKGROUND: yellow; PADDING-BOTTOM: 0in; BORDER-LEFT: navy 1pt solid; WIDTH: 27pt; PADDING-TOP: 0in; BORDER-BOTTOM: navy 1pt solid" vAlign=top width=36>
            <P style="MARGIN: 2pt 0in 0pt"><STRONG>&nbsp;</STRONG></P>
            </TD>
            <TD style="BORDER-RIGHT: navy 1pt solid; PADDING-RIGHT: 5.4pt; BORDER-TOP: #ece9d8; PADDING-LEFT: 5.4pt; BACKGROUND: yellow; PADDING-BOTTOM: 0in; BORDER-LEFT: #ece9d8; WIDTH: 613.9pt; PADDING-TOP: 0in; BORDER-BOTTOM: navy 1pt solid" width=819 colSpan=5>
            <P style="MARGIN: 2pt 0in 0pt"><SPAN><STRONG>Medium-Risk Issues</STRONG></SPAN></P>
            </TD>
        </TR>
    </TBODY>
HEADER_SECTION_MED
	foreach my $btid (keys %BTFINDINGS) {
		unless ($btid) { next; }	
		if  ($BTFINDINGS{$btid}{score} == 4) {
			#print "BT ID: $btid, PIDS: $BTFINDINGS{$btid}{pids}\n";
			$finding_num++;
			$finding_label="M".$finding_num."\.";
			print_html_report_row ($btid,$finding_label);
		}
	}
	# print out low risk finding section
	$finding_num=0;
	print OUT_MAPPED <<HEADER_SECTION_LOW;
    <TBODY>
        <TR>
            <TD style="BORDER-RIGHT: #ece9d8; PADDING-RIGHT: 5.4pt; BORDER-TOP: #ece9d8; PADDING-LEFT: 5.4pt; BACKGROUND: lime; PADDING-BOTTOM: 0in; BORDER-LEFT: navy 1pt solid; WIDTH: 27pt; PADDING-TOP: 0in; BORDER-BOTTOM: navy 1pt solid" vAlign=top width=36>
            <P style="MARGIN: 2pt 0in 0pt"><STRONG>&nbsp;</STRONG></P>
            </TD>
            <TD style="BORDER-RIGHT: navy 1pt solid; PADDING-RIGHT: 5.4pt; BORDER-TOP: #ece9d8; PADDING-LEFT: 5.4pt; BACKGROUND: lime; PADDING-BOTTOM: 0in; BORDER-LEFT: #ece9d8; WIDTH: 613.9pt; PADDING-TOP: 0in; BORDER-BOTTOM: navy 1pt solid" width=819 colSpan=5>
            <P style="MARGIN: 2pt 0in 0pt"><SPAN><STRONG>Low-Risk Issues</STRONG></SPAN></P>
            </TD>
        </TR>
    </TBODY>
HEADER_SECTION_LOW
	foreach my $btid (keys %BTFINDINGS) {
		unless ($btid) { next; }	
		if  ($BTFINDINGS{$btid}{score} == 3) {
			$finding_num++;
			$finding_label="L".$finding_num."\.";
			print_html_report_row ($btid,$finding_label);
		}
	}
	# print out testing note section
	$finding_num=0;
	print OUT_MAPPED <<HEADER_SECTION_NOTE;
    <TBODY>
        <TR>
            <TD style="BORDER-RIGHT: #ece9d8; PADDING-RIGHT: 5.4pt; BORDER-TOP: #ece9d8; PADDING-LEFT: 5.4pt; BACKGROUND: #cc99ff; PADDING-BOTTOM: 0in; BORDER-LEFT: navy 1pt solid; WIDTH: 27pt; PADDING-TOP: 0in; BORDER-BOTTOM: navy 1pt solid" vAlign=top width=36>
            <P style="MARGIN: 2pt 0in 0pt"><STRONG>&nbsp;</STRONG></P>
            </TD>
            <TD style="BORDER-RIGHT: navy 1pt solid; PADDING-RIGHT: 5.4pt; BORDER-TOP: #ece9d8; PADDING-LEFT: 5.4pt; BACKGROUND: #cc99ff; PADDING-BOTTOM: 0in; BORDER-LEFT: #ece9d8; WIDTH: 613.9pt; PADDING-TOP: 0in; BORDER-BOTTOM: navy 1pt solid" width=819 colSpan=5>
            <P style="MARGIN: 2pt 0in 0pt"><SPAN><STRONG>Testing Notes</STRONG></SPAN></P>
            </TD>
        </TR>
    </TBODY>
HEADER_SECTION_NOTE
	foreach my $btid (keys %BTFINDINGS) {
		unless ($btid) { next; }	
		if  ($BTFINDINGS{$btid}{score} == 2) {
			$finding_num++;
			$finding_label="N".$finding_num."\.";
			print_html_report_row ($btid,$finding_label);
		}
	}
	# print out HTML Footer - close out the HTML document
	print OUT_MAPPED "\<\/THEAD\>\<\/table\>\<\/body\>\<\/html\>";		
	if (defined $file_mapped) { 
		close(OUT_MAPPED);
		print "Save the found write-ups into BT EHCOE baseline report: $file_mapped ... Done!\n";
	}
}

sub print_html_report_row () {
    #
    ## Print out the html_report (BT EHCOE baseline report) one row at a time.
    #
	if ($verbose) { print "Print out BT EHCOE baseline report for BT finding ID: $_[0]\n"; }
	my (@SYSTEMS, @SERVICES, @PLUGIN_OUTPUTS);
	my $btid=$_[0];
	my @PIDS = split(/,/,$BTFINDINGS{$btid}{pids});
	foreach (@PIDS) {
		my $pid=$_;		
		if ($pid =~ /\d+/) {
			foreach (@{$FINDINGS{$pid}{systems}}) { push (@SYSTEMS, $_); }
			foreach (@{$FINDINGS{$pid}{services}}) { push (@SERVICES,$_); }
			foreach (@{$FINDINGS{$pid}{plugin_outputs}}) { push (@PLUGIN_OUTPUTS, $_);}
		}
	}
	print OUT_MAPPED <<COL_1;
        <TR>
            <TD style="BORDER-RIGHT: navy 1pt solid; PADDING-RIGHT: 5.4pt; BORDER-TOP: navy 1pt solid; PADDING-LEFT: 5.4pt; PADDING-BOTTOM: 0in; BORDER-LEFT: navy 1pt solid; WIDTH: 25.65pt; PADDING-TOP: 0in; BORDER-BOTTOM: navy 1pt solid; BACKGROUND-COLOR: transparent" vAlign=top width=34>
            <P style="MARGIN: 0in 0in 0pt 0.25in; TEXT-INDENT: -0.25in"><SPAN>
COL_1
			print OUT_MAPPED $_[1];
			print OUT_MAPPED <<COL_2;
</SPAN>&nbsp;</P>
            </TD>
            <TD style="BORDER-RIGHT: navy 1pt solid; PADDING-RIGHT: 5.4pt; BORDER-TOP: navy 1pt solid; PADDING-LEFT: 5.4pt; PADDING-BOTTOM: 0in; BORDER-LEFT: #ece9d8; WIDTH: 389.35pt; PADDING-TOP: 0in; BORDER-BOTTOM: navy 1pt solid; BACKGROUND-COLOR: transparent" vAlign=top width=386>
            <P style="MARGIN: 4pt 0in"><SPAN><STRONG>
COL_2
	my $Title = decode_entities($DBXML{$BTFINDINGS{$btid}{type}}{$BTFINDINGS{$btid}{vid}}{Title});
	print OUT_MAPPED $Title;
	print OUT_MAPPED "\<\/STRONG\>\<\/SPAN\>\<STRONG\> \<\/STRONG\>\<\/P\>";
	print OUT_MAPPED "\<P style\=\"MARGIN\: 4pt 0in\"\>\<em\>";
	my $Difficulty = decode_entities($DBXML{$BTFINDINGS{$btid}{type}}{$BTFINDINGS{$btid}{vid}}{Difficulty});
	print OUT_MAPPED $Difficulty;
	print OUT_MAPPED "\<\/em\>\<\/P\>";
	print OUT_MAPPED "\<table border\=1\>\<tr\>\<td\>Affected System\<\/td\>\<td\>Affected Service\<\/td\>\<\/tr\>";
	for(my $i=0;$i<=$#SYSTEMS;$i++) {
		print OUT_MAPPED "\<tr\>\<td\>";
		print OUT_MAPPED $SYSTEMS[$i];
		print OUT_MAPPED "\<\/td\>\<td\>";
		print OUT_MAPPED $SERVICES[$i];
		print OUT_MAPPED "\<\/td\>\<\/tr\>";
	}
	print OUT_MAPPED "\<\/table\>";
	# Insert weak cipher table for $btid 728
	if ($btid eq 728) { 
		print OUT_MAPPED "\<br\>BT successfully established SSL/TLS sessions with the following cipher\(s\)\:\<br\>"; 
		dump_weak_ciphers();
		print OUT_MAPPED "\<table border\=1\>\<tr\>\<td\>IP Address\<\/td\>\<td\>Protocol\<\/td\>\<td\>Cipher Suites with Weak Encryption\<\/td\>\<\/tr\>";
                for my $key ( keys %WC ) {
                	print OUT_MAPPED "\<tr\>\<td\>";
	        	print OUT_MAPPED $key;
			print OUT_MAPPED "\<\/td\>\<td\>";
                	print OUT_MAPPED $WC{$key}{prot};
			print OUT_MAPPED "\<\/td\>\<td\>";
                	print OUT_MAPPED $WC{$key}{cipher};
			print OUT_MAPPED "\<\/td\>\<\/tr\>";
		}
		print OUT_MAPPED "\<\/table\>";
          }
	print OUT_MAPPED "\<P style\=\"MARGIN\: 4pt 0in\"\>\<em\>";
	my $Description = decode_entities($DBXML{$BTFINDINGS{$btid}{type}} {$BTFINDINGS{$btid}{vid}}{Description});
	$Description =~ s/[^[:ascii:]]+//g;  		# get rid of non-ASCII characters
	$Description =~ s/IP.*DNS.*URI//g;		# get rid of the place-holder
	print OUT_MAPPED $Description;
	print OUT_MAPPED <<COL_3;
            </TD>
            <TD style="BORDER-RIGHT: navy 1pt solid; PADDING-RIGHT: 5.4pt; BORDER-TOP: navy 1pt solid; PADDING-LEFT: 5.4pt; PADDING-BOTTOM: 0in; BORDER-LEFT: #ece9d8; WIDTH: 51.6pt; PADDING-TOP: 0in; BORDER-BOTTOM: navy 1pt solid; BACKGROUND-COLOR: transparent" width=69>
            <P style="MARGIN: 4pt 0in"><STRONG>Open</STRONG></P>
            </TD>
COL_3
	print OUT_MAPPED<<COL_4;
            <TD style="BORDER-RIGHT: navy 1pt solid; PADDING-RIGHT: 5.4pt; BORDER-TOP: navy 1pt solid; PADDING-LEFT: 5.4pt; PADDING-BOTTOM: 0in; BORDER-LEFT: #ece9d8; WIDTH: 200pt; PADDING-TOP: 0in; BORDER-BOTTOM: navy 1pt solid; BACKGROUND-COLOR: transparent" vAlign=top width=266>
            <P style="MARGIN: 4pt 0in">
COL_4
	print OUT_MAPPED "\<P style\=\"MARGIN\: 4pt 0in\"\>\<em\>";
	my $Recommendation = decode_entities($DBXML{$BTFINDINGS{$btid}{type}}{$BTFINDINGS{$btid}{vid}}{Recommendation});
	$Recommendation =~ s/[^[:ascii:]]+//g;  	
	print OUT_MAPPED $Recommendation;
	print OUT_MAPPED "\<\/P\> \<\/TD\>";
	print OUT_MAPPED<<COL_5;
            <TD style="BORDER-RIGHT: navy 1pt solid; PADDING-RIGHT: 5.4pt; BORDER-TOP: navy 1pt solid; PADDING-LEFT: 5.4pt; PADDING-BOTTOM: 0in; BORDER-LEFT: #ece9d8; WIDTH: 274.3pt; PADDING-TOP: 0in; BORDER-BOTTOM: navy 1pt solid; BACKGROUND-COLOR: transparent" vAlign=top width=260>
            <P style="MARGIN: 4pt 0in">
COL_5
	print OUT_MAPPED "\<table border\=1\>\<tr\>\<td\>NessusID\<\/td\><\/tr\>";
	foreach (@PIDS) {
		if (/\d+/) {
			print OUT_MAPPED "\<TR\>\<TD\>",$_,"\<\/TD\>\<\/TR\>";
		}
	}
	print OUT_MAPPED "\<\/table\>";
	print OUT_MAPPED<<COL_6;
            <TD style="BORDER-RIGHT: navy 1pt solid; PADDING-RIGHT: 5.4pt; BORDER-TOP: navy 1pt solid; PADDING-LEFT: 5.4pt; PADDING-BOTTOM: 0in; BORDER-LEFT: #ece9d8; WIDTH: 274.3pt; PADDING-TOP: 0in; BORDER-BOTTOM: navy 1pt solid; BACKGROUND-COLOR: transparent" vAlign=top width=250>
            <P style="MARGIN: 4pt 0in">
COL_6
	print OUT_MAPPED "\<table border\=1\>\<tr\>\<td\>System\<\/td\>\<td\>Service\<\/td\>\<td\>Nessus Evidence\<\/td\>\<\/tr\>";
	for(my $i=0;$i<=$#SYSTEMS;$i++) {		
		print OUT_MAPPED "\<tr\>\<td\>";
		print OUT_MAPPED $SYSTEMS[$i],"\<\/td\>\<td\>";
		print OUT_MAPPED $SERVICES[$i];
		print OUT_MAPPED "\<\/td\>\<td\>";
		if ($PLUGIN_OUTPUTS[$i]) { 
			print OUT_MAPPED $PLUGIN_OUTPUTS[$i];
		} else {
			print OUT_MAPPED "none available";
		}
		print OUT_MAPPED "\<\/td\>\<\/tr\>";
	}
	print OUT_MAPPED "\<\/table\>\<br\>";
	print OUT_MAPPED "\<\/P\> \<\/TD\> \<\/TR\>";
}
	
sub print_banner () {
    #
    ## Print program header in the beautiful ascii art format - you know graphic count :-) 
    #
	print "ooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo\n\n";
	print "8888ba.88ba   .d888888  dP     dP  88888888b  888888ba  dP  a88888b. dP     dP 
88  `8b  `8b d8'    88  88     88  88         88    `8b 88 d8'   `88 88   .d8' 
88   88   88 88aaaaa88a 88    .8P a88aaaa    a88aaaa8P' 88 88        88aaa8P'  
88   88   88 88     88  88    d8'  88         88   `8b. 88 88        88   `8b. 
88   88   88 88     88  88  .d8P   88         88     88 88 Y8.   .88 88     88 
dP   dP   dP 88     88  888888'    88888888P  dP     dP dP  Y88888P' dP     dP \n";
	print "\nVersion: $ver, designed and developed by $author\nooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo\n\n";	
}
