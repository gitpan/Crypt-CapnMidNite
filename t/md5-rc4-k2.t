#!/usr/bin/perl
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

# version 1.01 10-14-00 michael@bizsystems.com

BEGIN { $| = 1; print "1..25\n"; }
END {print "not ok 1\n" unless $loaded;}

my $module = do './name';
eval "use $module";

$loaded = 1;
print "ok 1\n";

my $DEBUG = 0;	# turns on subroutine "show"

sub RC4 {
  my ($pass, $txt) = @_;
  my $c = &_RC4(@_);
  $c->crypt($txt);
}

sub RC4encrypt {
  my ($pass, $txt) = @_;
  my $c = &_RC4(@_);
  return $c->encrypt($txt);
}

my $using_md5 = 0;		# first pass

sub _RC4 {
  my ($pass, $txt,$x,$y) = @_;
  my $pass1 = ($using_md5) ? 'ef012345' : 'f915ed2b8f05535d31bf675fbc193dfc';
  $pass1 = pack('H*', $pass1);
  my $c;
  $c = ($using_md5) 
	? new_md5_crypt ${module}($pass1,$pass) 
	: new_crypt ${module}($pass1,$pass);

  $c->x($x);
  $c->y($y);
  return $c;
}

##########################################################
local($x,$y) = @ARGV;
$x = 0 unless $x;
$y = 0 unless $y;

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
	'fa93cc58ced3c1a8',	# expected encrypted value
	'bb1bb51296def253',	# ex B
	'1a15f79ffbc20e60',	# ex C

  ],
  [# test 3 pv, pt, en
	'0123456789abcdef',
	'68652074696d6520',
	'281f067e0f5e9037',
	'69977f345753a3cc',
	'c8993db93a4f5fff',
  ],
  [# test 4 pv, pt, en
	'ef012345',
	'00000000000000000000',
	'f8d54696dd845a77bb10',
	'b95d3fdc8589698c13ab',
	'18537d51e89595bfb1d8',
  ],
  [# test 5
	'87ce0e9870a0d26ec0d1ebe00ebe0d1bee0beabc0018052fed0270d1e0088dc0a7d0a052dd5e002b507a6ed0085d258c4ce0',
	'd1e0ae2c40bb8070f8103e69ed08feb0d1e05a320d80012345678900d1e0ae2c40bb8070f8103e69ed08feb0d1e05a320d80',
	'5b141bce5df35b974a3023e4af5deaed3fb3e3b8f1743d8ccc1f0174fb7628b4113520ebcb5a335ba923ff97889716c233a3',
	'1a9c628405fe686ce28b075788ccc61c1da0688f6fdf5f005b2b67fbade0d79c202655e9935fd894813628555d932c12e5e0',
	'bb92200968e2945f40f8816aad5c41d82a9c220b52470f3cda619ce8e1255a482de748d282ce27136d5455aaa717ff40f6fc',
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

while ( $using_md5 < 2) {
  my $ap = $o;	# starting test array pointer
  my $ep = 0;	# starting encryption pointer

  while ( 1 ) {
    my $x = $v[0]->[$ep];
    my $y = $v[1]->[$ep];

    my $passphrase = pack('H*', $v[$ap]->[0]);
    my $plaintext = pack('H*', $v[$ap]->[1]);
    my $encrypted = ($module =~ /LockTite/)
	? &RC4encrypt( $passphrase, $plaintext, $x, $y )
	: pack('H*',$v[$ap]->[$ep+2]);
    my $decrypt = RC4( $passphrase, $encrypted, $x, $y );

   &show('pass','txt','decrypt','encrypt','expect',
	$passphrase,$plaintext,$decrypt,$encrypted,pack('H*',$v[$ap]->[$ep+2]));
    if (($encrypted ne pack('H*', $v[$ap]->[$ep+2])) || 
	($decrypt ne $plaintext)) {
      print 'encrypted=', unpack('H*',$encrypted), "\n expected=$v[$ap]->[$ep+2]\n";
      print 'decrypted=', unpack('H*',$decrypt), "\nplaintext=", unpack('H*',$plaintext), "\n";
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
  ++$using_md5;
}
