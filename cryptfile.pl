#!/usr/bin/perl
#
# cryptfile.pl
# version 2.01 9-22-02 michael@bizsystems.com
#
# encrypt or decrypt a file
#
use strict;
use diagnostics;
use Crypt::C_LockTite;

local (*I, *O);

unless (@ARGV == 3) {
  print 'syntax: cryptfile.pl e|d in_file out_file'."\n";
  exit;
}
unless ( -e $ARGV[1] ) {
  print "could not find input file $ARGV[1]\n";
  exit;
}
unless (open(I,$ARGV[1])) {
  print "could not open input file $ARGV[1]\n";
  exit;
}
unless (open(O,">$ARGV[2]")) {
  print "could not open output file $ARGV[2]\n";
  exit;
}
if ( $ARGV[0] =~ /^e$/i ) {
  my $crypt = Crypt::C_LockTite->new_md5_crypt($ARGV[2]);
  $crypt->encrypt_fileIO(*I,*O);
} else {
  my $crypt = Crypt::C_LockTite->new_md5_crypt($ARGV[1]);
  $crypt->decrypt_fileIO(*I,*O);
}
close I;
close O;
