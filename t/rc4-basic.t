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
  my ($pass,$txt,$x,$y) = @_;
  my $c = new_rc4 ${module}($pass);
  $c->x($x);
  $c->y($y);
  $c->rc4($txt);
}

##########################################################
local($x,$y) = @ARGV;
$x = 0 unless $x;
$y = 0 unless $y;

local $DEBUG = 1;

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
	'75b7878099e0c596',	# expected encrypted value
	'c110cfd12da3f27b',	# ex B
	'1a64796f84fb87e3',	# ex C
  ],
  [# test 3 pv, pt, en
	'0123456789abcdef',
	'68652074696d6520',
	'1cf1e29379266d59',
	'a856aac2cd655ab4',
	'73221c7c643d2f2c',
  ],
  [# test 4 pv, pt, en
	'ef012345',
	'00000000000000000000',
	'd6a141a7ec3c38dfbd61',
	'e54f77ecf98de973cf3a',
	'66bbad85d51cdd9f6433',
  ],
  [# test 5
	'87ce0e9870a0d26ec0d1ebe00ebe0d1bee0beabc0018052fed0270d1e0088dc0a7d0a052dd5e002b507a6ed0085d258c4ce0',
	'd1e0ae2c40bb8070f8103e69ed08feb0d1e05a320d80012345678900d1e0ae2c40bb8070f8103e69ed08feb0d1e05a320d80',
	'079f4605858e9b2dd5159e7404452c50a61f45ff46d7209d8848371d44b51b93a3d6ead105a3cb532eaab27a7da54267efef',
	'f19f47134a8cba5dee95fae0391f8878f136cf2da8dc8aee79b5940a842676c695955623d7b3f954701b483b84abd5703b23',
	'0d84594040960c939ddee5614a5123b8bbb24791664d609d5873dc52f4735b0f843e990e41cb2cb58bc7ff001a4e8c3ff94f',
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

