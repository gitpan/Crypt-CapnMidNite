#!/usr/bin/perl
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

# version 1.01 10-14-00 michael@bizsystems.com

BEGIN { $| = 1; print "1..13\n"; }
END {print "not ok 1\n" unless $loaded;}

my $module = do './name';
eval "use $module";

$loaded = 1;
print "ok 1\n";

sub RC4 {
  my ($pass, $txt,$x,$y) = @_;
  my $c = new_md5_rc4 ${module}($pass);
  $c->x($x);
  $c->y($y);
  $c->rc4($txt);
}

##########################################################
local($x,$y) = @ARGV;
$x = 0 unless $x;
$y = 0 unless $y;

local $DEBUG = 0;

# test values arranged as pointers to array of
# x vals	x,x,x,x..
# y vals	y,y,y,y....
# pv	passphrase value
# pt	plaintext value
# ex	expected encrypted value
# $v[n]->[0] = pv, etc...

local @v = (

  [0,1,3,],		# x values
  [0,2,255],		# y values

  [# test 2 pv, pt, enA, enB, enC for subsequent test runs
	'0123456789abcdef',	# passphrase
	'0123456789abcdef',	# plaintext
	'fb9fcaa91770377f',	# expected encrypted value
	'a1a3f9431a116987',	# ex B
	'6e95dfa95ff359f4',	# ex C

  ],
  [# test 3 pv, pt, en
	'0123456789abcdef',
	'68652074696d6520',
	'92d9afbaf7b69fb0',
	'c8e59c50fad7c148',
	'07d3bababf35f13b',
  ],
  [# test 4 pv, pt, en
	'ef012345',
	'00000000000000000000',
	'7cea234bee422dbbdd08',
	'dcae9f6ec2c4b44689d5',
	'0ca9bea874cacadfd86c',
  ],
  [# test 5
	'87ce0e9870a0d26ec0d1ebe00ebe0d1bee0beabc0018052fed0270d1e0088dc0a7d0a052dd5e002b507a6ed0085d258c4ce0',
	'd1e0ae2c40bb8070f8103e69ed08feb0d1e05a320d80012345678900d1e0ae2c40bb8070f8103e69ed08feb0d1e05a320d80',
	'8306ce3f57fa1182a232319f01ab708aea1b35d40c02754c8fd42b861f6d6b9e0cd14b51d609d5c1c8ad2942d9dd2cde915a',
	'88ae499183f2c7b907565e84d59ba422df7ad0c7c49b9e45fbf2a30d689d3cd38ac3f220f0fa88e2ac6dc2f8623dc2ff00a6',
	'a7d9775e2b536e8f229691a4349ff83fe85c116a1d77bf2c6f518d79341fcafb6f15ff5686bcab9321e33c0330e60b8f33fc',
  ],

);

sub show {
  return unless $DEBUG;
  $i=0;
  while ( $i <= $#_/2 ) {
    print $_[$i++]; }
  continue {
    print ', ';
  }
  print "\n";
  for (; $i <= $#_; $i++ ) {
    print "'", unpack('H*', $_[$i]), "',\n";
  }
}

######################### End of black magic.

# Insert your test code below (better if it prints "ok 13"
# (correspondingly "not ok 13") depending on the success of chunk 13
# of the test code):

#
# test vectors are from:
#
#        Legion of The Bouncy Castle Java Crypto Libraries http://www.bouncycastle.org
# and    Crypto++ 3.2 http://www.eskimo.com/~weidai/cryptlib.html
#

my $o = 2;	# offset into array for first test (disgard x,y arrays)

my $test = 2;	# starting test number
my $ap = $o;	# starting test array pointer
my $ep = 0;	# starting encryption pointer

while ( 1 ) {
  my $x = $v[0]->[$ep];
  my $y = $v[1]->[$ep];

  my $passphrase = pack('H*', $v[$ap]->[0]);
  my $plaintext = pack('H*', $v[$ap]->[1]);
  my $encrypted = RC4( $passphrase, $plaintext, $x, $y );
  my $decrypt = RC4( $passphrase, $encrypted, $x, $y );
  &show('pass','txt','decrypt','encrypt','expect',
	$passphrase,$plaintext,$decrypt,$encrypted,pack('H*',$v[$ap]->[$ep+2]));
  if (($encrypted ne pack('H*', $v[$ap]->[$ep+2])) || 
	($decrypt ne $plaintext)) {
    print 'not ';
  }
  print "ok $test\n";
  ++$test;
  ++$ap;
  next if $ap <= $#v;
  $ap = $o;
  ++$ep;
  last if $ep > $#{$v[0]};
}

