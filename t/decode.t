#!/usr/bin/perl
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

# version 1.01 12-1-00 michael@bizsystems.com

BEGIN { $| = 1; print "1..3\n"; }
END {print "not ok 1\n" unless $loaded;}

my $module = do './name';
eval "use $module";

$loaded = 1;
print "ok 1\n";

$test = 2;
foreach(0..1) {
  my $key = '12345';
  my $daty = 'abcdefg123456';
  my $kex = $key;
  my $datx = $daty;

  my $ox = $module->decode($kex,$datx);
  my $oy = ($_)		# use returned object from decode ONCE
	? $ox->new_md5_crypt($key)->crypt($daty)
	: $module->new_md5_crypt($key)->crypt($daty);

  print 'not ' unless $datx eq $oy;
  print "ok $test\n";
  ++$test;
}
