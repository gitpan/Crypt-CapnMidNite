#!/usr/bin/perl

BEGIN {print "1..7\n";}
END {print "not ok 1\n" unless $loaded;}

#use diagnostics;

my $module = do './name';
eval "use $module";

$loaded = 1;
print "ok 1\n";

my $md5 = new $module;

sub digest_file
{
    my($file, $method) = @_;
    $method ||= "digest";
    #print "$file $method\n";

    open(F, $file) or die "Can't open $file: $!";
    binmode(F);
    my $digest = $module->new->addfile(*F)->$method();
    close(F);

    $digest;
}

sub cat_file
{
    my($file) = @_;
    local $/;  # slurp
    open(F, $file) or die "Can't open $file: $!";
    binmode(F);
    my $tmp = <F>;
    close(F);
    $tmp;
}

sub md5 {
  if ( $module eq 'Digest::MD5' ) {
    Digest::MD5::md5(@_);
  } else {
    $md5->md5(@_);
  }
}

sub md5_hex {
  if ( $module eq 'Digest::MD5' ) {
    Digest::MD5::md5_hex(@_);
  } else {
    $md5->md5_hex(@_);
  }
}

sub md5_base64 {
  if ( $module eq 'Digest::MD5' ) {
    Digest::MD5::md5_base64(@_);
  } else {
    $md5->md5_base64(@_);
  }
}

#
# This is the output of: 'md5sum rfc1321.txt rfc1321.txt.bin rfc1321.txt.md5.bin rfc2104.txt rfc2104.txt.bin rfc2104.txt.md5.bin'
#
my $EXPECT = <<EOT;
754b9db19f79dbc4992f7166eb0f37ce  rfc1321.txt
174e5de0e820c285e905ab3aad616884  rfc1321.txt.bin
8b54723bef1592c5598082116e729bbd  rfc1321.txt.md5.bin
d108e0788d01554ad3d1cd49558b2d20  rfc2104.txt
12ea545998b98577f1fc183de931487f  rfc2104.txt.bin
a23eab3c1c4f6972ed109a7771e83b35  rfc2104.txt.md5.bin
EOT

if (!(-f "README") && -f "../README") {
   chdir("..") or die "Can't chdir: $!";
}

my $testno = 1;

my $B64 = 1;
eval { require MIME::Base64; };
if ($@) {
     print $@;
     print "Will not test base64 methods\n";
     $B64 = 0;
}

for (split /^/, $EXPECT) {
     my($md5hex, $file) = split '\s+';
     #print 'f=', $md5hex, ' ', $file, "\n";
     my $md5bin = pack("H*", $md5hex);
     my $md5b64; 
     if ( $B64 ) {
	 $md5b64 = MIME::Base64::encode($md5bin, "");
	 chop($md5b64); chop($md5b64);	# remove padding
     }

     my $failed;

     if (digest_file($file, 'digest') ne $md5bin) {
	 print "$file: Bad digest\n";
	 $failed++;
     }
     if (digest_file($file, 'hexdigest') ne $md5hex) {
	 print "$file: Bad hexdigest\n";
	 $failed++;
     }
     if ($B64 && digest_file($file, 'b64digest') ne $md5b64) {
         print "$file: Bad b64digest\n";
         $failed++;
     }

     my $data = cat_file($file);
     if (md5($data) ne $md5bin) {
	 print "$file: md5() failed md5 bin\n";
	 $failed++;
     }
     if (md5_hex($data) ne $md5hex) {
	 print "$file: md5_hex() failed md5 hex\n";
	 $failed++;
     }
     if ($B64 && md5_base64($data) ne $md5b64) {
         print "$file: md5_base64() failed\n";
print 'got=', $B64 && md5_base64($data), "\nyes=$md5b64\n";
         $failed++;
     }

     if ($module->new->add($data)->digest ne $md5bin) {
	 print "$file: MD5->new->add(...)->digest failed add file md5\n";
	 $failed++;
     }
     if ($module->new->add($data)->hexdigest ne $md5hex) {
	 print "$file: MD5->new->add(...)->hexdigest failed add file md5hex\n";
	 $failed++;
     }
     if ($B64 && $module->new->add($data)->b64digest ne $md5b64) {
         print "$file: MD5->new->add(...)->b64digest failed\n";
         $failed++;
     }

     my @data = split //, $data;
     if (md5(@data) ne $md5bin) {
	 print "$file: md5(\@data) failed md5 by character\n";
	 $failed++;
     }

     if ($module->new->add(@data)->digest ne $md5bin) {
	 print "$file: MD5->new->add(\@data)->digest failed md5 add by character\n";
	 $failed++;
     }
     $md5 = $module->new;
     for (@data) {
	 $md5->add($_);
     }
     if ($md5->digest ne $md5bin) {
	 print "$file: $md5->add()-loop failed\n";
	 $failed++;
     }

     print "not " if $failed;
     print "ok ", ++$testno, "\n";
}


