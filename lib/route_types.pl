#!/usr/bin/perl
# SPDX-License-Identifier: GPL-2.0-or-later
##
## Scan a file of route-type definitions (see eg route_types.txt) and
## generate a corresponding header file with:
##
## - enum of Zserv route-types
## - redistribute strings for the various Quagga daemons
##
## See route_types.txt for the format.
##
##
## Copyright (C) 2009 David Lamparter.
##

use strict;
use Getopt::Long;

# input processing
#
my @protos;
my %protodetail;

my %daemons;

my @enabled;

GetOptions ("enabled=s" => \@enabled);
@enabled = split(/,/,join(',',@enabled));

while (<STDIN>) {
	# skip comments and empty lines
	next if (/^\s*(#|$)/);

	# strip whitespace
	chomp;
	$_ =~ s/^\s*//;
	$_ =~ s/\s*$//;

	# match help strings
	if (/^(ZEBRA_ROUTE_[^\s]+)\s*,\s*"(.*)"$/) {
		$protodetail{$1}->{'longhelp'} = $2;
		next;
	}

	$_ =~ s/\s*,\s*/,/g;

	# else: 8-field line
	my @f = split(/,/, $_);
	unless (@f == 9 || @f == 10) {
		die "invalid input on route_types line $.\n";
	}

	my $proto = $f[0];
	$f[3] = $1 if ($f[3] =~ /^'(.*)'$/);
	$f[7] = $1 if ($f[7] =~ /^"(.*)"$/);

	$protodetail{$proto} = {
		"number" => scalar @protos,
		"type" => $f[0],
		"cname" => $f[1],
		"daemon" => $f[2],
		"char" => $f[3],
		"ipv4" => int($f[4]),
		"ipv6" => int($f[5]),
		"redist" => int($f[6]),
		"shorthelp" => $f[7],
		"enabled" => $f[8],
		"restrict2" => $f[9],
	};
	push @protos, $proto;
	$daemons{$f[2]} = {
		"ipv4" => int($f[4]),
		"ipv6" => int($f[5])
	} unless ($f[2] eq "NULL");
}

# output
printf <<EOF, $ARGV[0];
/* Auto-generated from route_types.txt by %s. */
/* Do not edit! */

#ifndef _FRR_ROUTE_TYPES_H
#define _FRR_ROUTE_TYPES_H

/* Zebra route's' types. */
EOF

push @protos, "ZEBRA_ROUTE_MAX";
my (@protosv4, @protosv6) = ((), ());
for (my $c = 0; $c < @protos; $c++) {
	my $p = $protos[$c];
	printf "#define %-32s %d\n", $p, $c;
	push @protosv4, $p if ($protodetail{$p}->{"ipv4"});
	push @protosv6, $p if ($protodetail{$p}->{"ipv6"});
}
pop @protos;

sub codelist {
	my (@protos) = @_;
	my (@lines) = ();
	my $str = "  \"Codes: ";
	for my $p (@protos) {
		next unless (grep $_ eq $protodetail{$p}->{"enabled"}, @enabled);
		my $s = sprintf("%s - %s, ",
			$protodetail{$p}->{"char"},
			$protodetail{$p}->{"shorthelp"});
		if (length($str . $s) > 70) {
			$str =~ s/ $//;
			push @lines, $str . "\\n\" \\\n";
			$str = "  \"       ";
		}
		$str .= $s;
	}
	$str =~ s/ $//;
	push @lines, $str . "\\n\" \\\n";
	push @lines, "  \"       > - selected route, * - FIB route, q - queued, r - rejected, b - backup\\n\"";
	push @lines, "  \"       t - trapped, o - offload failure\\n\\n\"";


	return join("", @lines);
}

print "\n";
printf "#define SHOW_ROUTE_V4_HEADER \\\n%s\n", codelist(@protosv4);
printf "#define SHOW_ROUTE_V6_HEADER \\\n%s\n", codelist(@protosv6);
print "\n";

sub collect {
	my ($daemon, $ipv4, $ipv6, $any, $ip_prot) = @_;
	my (@names, @help) = ((), ());
	for my $p (@protos) {
		next if ($ip_prot == 1 && $daemon eq "zebra" && $protodetail{$p}->{"cname"} eq "kernel");
		next if ($ip_prot == 1 && $daemon eq "zebra" && $protodetail{$p}->{"cname"} eq "connected");
		next if ($ip_prot == 1 && $daemon eq "zebra" && $protodetail{$p}->{"cname"} eq "local");
		next if ($protodetail{$p}->{"daemon"} eq $daemon && $daemon ne "zebra");
		next if ($protodetail{$p}->{"restrict2"} ne "" && 
		         $protodetail{$p}->{"restrict2"} ne $daemon);
		next if ($protodetail{$p}->{"redist"} eq 0);
		next unless (grep $_ eq $protodetail{$p}->{"enabled"}, @enabled);
		next unless (($ipv4 && $protodetail{$p}->{"ipv4"})
			     || ($ipv6 && $protodetail{$p}->{"ipv6"}));
		push @names, $protodetail{$p}->{"cname"};
		push @help, "  \"".$protodetail{$p}->{"longhelp"}."\\n\"";
	}
	if ($any == 1) {
		push @names, "any";
		push @help, "  \"Any of the above protocols\\n\"";
	}
	return ("\"<" . join("|", @names) . ">\"", join(" \\\n", @help));
}

for my $daemon (sort keys %daemons) {
	next unless ($daemons{$daemon}->{"ipv4"} || $daemons{$daemon}->{"ipv6"});
	printf "/* %s */\n", $daemon;
	if ($daemons{$daemon}->{"ipv4"} && $daemons{$daemon}->{"ipv6"}) {
		my ($names, $help) = collect($daemon, 1, 1, 0, 0);
		printf "#define FRR_REDIST_STR_%s \\\n  %s\n", uc $daemon, $names;
		printf "#define FRR_REDIST_HELP_STR_%s \\\n%s\n", uc $daemon, $help;

		($names, $help) = collect($daemon, 1, 0, 0, 0);
		printf "#define FRR_IP_REDIST_STR_%s \\\n  %s\n", uc $daemon, $names;
		printf "#define FRR_IP_REDIST_HELP_STR_%s \\\n%s\n", uc $daemon, $help;

		($names, $help) = collect($daemon, 0, 1, 0, 0);
		printf "#define FRR_IP6_REDIST_STR_%s \\\n  %s\n", uc $daemon, $names;
		printf "#define FRR_IP6_REDIST_HELP_STR_%s \\\n%s\n", uc $daemon, $help;

		if ($daemon eq "zebra") {
			($names, $help) = collect($daemon, 1, 0, 1, 1);
			printf "#define FRR_IP_PROTOCOL_MAP_STR_%s \\\n  %s\n", uc $daemon, $names;
			printf "#define FRR_IP_PROTOCOL_MAP_HELP_STR_%s \\\n%s\n", uc $daemon, $help;

			($names, $help) = collect($daemon, 0, 1, 1, 1);
			printf "#define FRR_IP6_PROTOCOL_MAP_STR_%s \\\n  %s\n", uc $daemon, $names;
			printf "#define FRR_IP6_PROTOCOL_MAP_HELP_STR_%s \\\n%s\n", uc $daemon, $help;
		}
	} else {
		my ($names, $help) = collect($daemon,
			$daemons{$daemon}->{"ipv4"}, $daemons{$daemon}->{"ipv6"}, 0);
		printf "#define FRR_REDIST_STR_%s \\\n  %s\n", uc $daemon, $names;
		printf "#define FRR_REDIST_HELP_STR_%s \\\n%s\n", uc $daemon, $help;
	}
	print "\n";
}

print <<EOF;

#ifdef FRR_DEFINE_DESC_TABLE

struct zebra_desc_table
{
  unsigned int type;
  const char *string;
  char chr;
};

#define DESC_ENTRY(T,S,C) [(T)] = { (T), (S), (C) }
static const struct zebra_desc_table route_types[] = {
EOF

for (my $c = 0; $c < @protos; $c++) {
	my $p = $protos[$c];
	printf "  DESC_ENTRY\t(%s\t \"%s\",\t'%s' ),\n",
	       $p.",", $protodetail{$p}->{"cname"}, $protodetail{$p}->{"char"};
}

print <<EOF;
};
#undef DESC_ENTRY

#endif /* FRR_DEFINE_DESC_TABLE */

#endif /* _FRR_ROUTE_TYPES_H */
EOF

