#!/usr/bin/perl
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

# version 1.01 12-1-00 michael@bizsystems.com

BEGIN { $| = 1; print "1..11\n"; }
END {print "not ok 1\n" unless $loaded;}

my $module = do './name';
eval "use $module";

$loaded = 1;
print "ok 1\n";

$test = 2;

# for ID = '12345', seed = 'BizSystems';
my $MAC_txt	= 'MAC generator text';
my $expected	= 'this is the crypt text';
my $CRYPT_hex	= '9e70d061b3942222ddd44bdbb47000a3d70251c890b5';
# the key is the time in seconds from the epoch
my $failtime = 960000000;						# Jun 2000
my %keys	= (
	2147000000	=>	'4927a289d5308320bb88b4b0d408c148',	# Jan 2038
	2147000001	=>	'28850e5f577d83cad046f9d99594df76',
	$failtime	=>	'cc7ddc51f5d967e6b2f4a566a408b63e',	# see failtime above
	0		=>	'f69809f8c9c2110a4f34f2e368daac42',
);

my $bu = $module->new;
my $time = time;
my $margin = 5;
foreach(sort {$b <=> $a } keys %keys) {
  my $crypt_txt = pack('H*', $CRYPT_hex);
  my $n = 4;
  my $c1 = substr($crypt_txt,0,$n);
  my $c2 = substr($crypt_txt,$n);

#	mac txt, exp,key val, encrypted txt
  @_ = ($MAC_txt,$_,$keys{$_});
  my $xtxt = ($_ < time && $_ != 0) ? undef : $expected;
  $bu->reset;
  my $exp =$bu->license(@_) || 0;
  print "bad expiration time $_\nnot " unless ($failtime == $_ && !$exp) ||
	(!$_ && $exp < $time + $margin && $exp > $time - $margin) ||
	($exp < $_ - $time + $margin && $exp > $_ - $time - $margin);
  print "ok $test\n";
  ++$test;
  if ($exp) {
    $bu->crypt($c1);
    $bu->crypt($c2);
    $_ = $c1.$c2;
  } else {
    $_ = '';
  }
  print "text does not match\nnot " unless 0|| (!$xtxt && !$_) || ($xtxt eq $_);
  print "ok $test\n";
  ++$test;
}

# test file operation
local (*IN,*OUT);
my $plain_file	= 'rfc1321.txt';
my $crypt_file	= 'rfc1321.txt.lic';

sub slurp {
  my($in) = @_;
  open(IN,$in);
  read(IN,$in,(stat(IN))[7]);
  close IN;
  return $in;
}
use diagnostics;
my $plain_txt = &slurp($plain_file);

foreach my $key (sort {$b <=> $a } keys %keys) {
next if $key <= $failtime;
  my $crypt_txt = '';
  @_ = ($MAC_txt,$key,$keys{$key});
  $bu->reset;
  $bu->license(@_);
  print "file text mis-match\nnot " unless (
	open(IN, $crypt_file) &&
	open(OUT,">delete.me") &&
	$bu->decrypt_fileIO(*IN,*OUT) &&
	close IN &&
	close OUT &&
	($crypt_txt = &slurp('delete.me')) &&
	(	$key > $failtime && $plain_txt eq $crypt_txt ||
		$key <= $failtime && $plain_txt ne $crypt_txt ));
  unlink 'delete.me';
  print "ok $test\n";
  ++$test;
}
