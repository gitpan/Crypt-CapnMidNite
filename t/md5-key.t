#!/usr/bin/perl
######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN {print "1..3\n";}
END {print "not ok 1\n" unless $loaded;}

#use diagnostics;

my $module = do './name';
eval "use $module";

$loaded = 1;
print "ok 1\n";

######################### End of black magic.

# Insert your test code below (better if it prints "ok 13"
# (correspondingly "not ok 13") depending on the success of chunk 13
# of the test code):

package MD5Test;

# 2: Basic test data as defined in RFC 1321
#    Plus check of x,y coordinates for RC4 state
#  key => [data,x,y]

%data = (
	 ""	=> ["d41d8cd98f00b204e9800998ecf8427e",193,136,],
	 "a"	=> ["0cc175b9c0f1b6a831c399e269772661",80,144,],
	 "abc"	=> ["900150983cd24fb0d6963f7d28e17f72",39,129,],
	 "message digest"
		=> ["f96b697d7cb7938d525a2f31aaf161d0",253,120,],
	 "abcdefghijklmnopqrstuvwxyz"
		=> ["c3fcd3d76192e4007dfb496cca67e13b",76,110,],
	 "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
		=> ["d174ab98d277d9f5a5611c2c9f419d9f",36,229,],
	 "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
		=> ["57edf4a22be3c955ac49da2e2107b67a",156,191,],
);

$failed = 0;
foreach (sort(keys(%data)))
{
    $md5_key1 = new_md5_rc4 $module($_);
    $digest = $md5_key1->digest;
    $hex = unpack("H*", $digest);
    if ($hex ne $data{$_}[0]) {
        print "\$md5_key1->digest: $_\n";
        print "expected: $data{$_}[0]\n",
                     "got     : $hex\n";
	$failed++;
    }

    my $rv = $md5_key1->hexdigest;
    if ($rv ne $hex ) {
	print "\$md5_key1->hexdigest($_) failed\n";
	print "expect $data{$_}[0]\ngot    ($rv)\n";
	$failed++;
    }
}
print ($failed ? "not ok 2\n" : "ok 2\n");

foreach (sort(keys(%data)))
{
    $md5_key2 = new_md5_crypt $module($_);
    $digest = $md5_key2->digest;
    $hex = unpack("H*", $digest);
#    print 'key=',$_,"\n",'hash x=', $md5_key2->hx, ' y=', $md5_key2->hy, "\n";
    if ($hex ne $data{$_}[0]) {
        print "\$md5_key2->digest: $_\n";
        print "expected: $data{$_}[0]\n",
                     "got     : $hex\n";
	$failed++;
    }

    my $rv = $md5_key2->hexdigest;
    if ($rv ne $hex ) {
	print "\$md5_key2->hexdigest($_[0]) failed\n";
	print "expect $data{$_[0]}\ngot    ($rv)\n";
	$failed++;
    }

    my $hx = $md5_key2->hx;
    my $hy = $md5_key2->hy;
    my $x = $md5_key2->x;
    my $y = $md5_key2->y;

    if ( $hx ne $data{$_}[1] ) {
	print "hx=$hx, should be $data{$_}[1]\n";
	$failed++;
    }

    if ( $hy ne $data{$_}[2] ) {
	print "hy=$hy, should be $data{$_}[2]\n";
	$failed++;
    }

    if ( $x ne $data{$_}[1] ) {
	print "x=$x, should be $data{$_}[1]\n";
	$failed++;
    }

    if ( $y ne $data{$_}[2] ) {
	print "y=$y, should be $data{$_}[2]\n";
	$failed++;
    }

}
print ($failed ? "not ok 3\n" : "ok 3\n");
