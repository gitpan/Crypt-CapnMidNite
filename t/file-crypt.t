#!/usr/bin/perl

############ We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN {print "1..9\n";}
END {print "not ok 1\n" unless $loaded;}

#use diagnostics;

my $module = do './name';
eval "use $module";

$loaded = 1;
print "ok 1\n";
               
my $usepipes = 0;
# can do this without tmp files, but crashes on older perl versions
#$usepipes = 1 if $] >= 5.006;	# may be slower?	 !!

# [filename, md5 4 crypt, md5 4 md5crypt, md5 4 encode, md5 4 md5 encode]

my @v = (
[
	'rfc2104.txt',				# file
	'08d208f98471f823fe8e99e7fa6563a2',	# md5 for crypt
	'0b0f24854b5377bc7c5a35b969574e6f',	# md5 for md5_crypt
	'12ea545998b98577f1fc183de931487f',	# md5 for encode
	'a23eab3c1c4f6972ed109a7771e83b35',	# md5 for md5 encode
],
[
	'rfc1321.txt',
	'91b95a4ae4f8baa2cb7568d17f8df750',
	'9cb09e680990a69c408754b7ea8e307e',
	'174e5de0e820c285e905ab3aad616884',
	'8b54723bef1592c5598082116e729bbd',
],
);

my $fa		= 'delete.me.tmp';
my $fb		= 'delete.me2.tmp';

my $testno	= 2;

# test vectors
my $file	= 0;
my $crypt	= 1;
my $md5cr	= 2;
my $encode	= 3;
my $md5enc	= 4;

my $lastcrypt	= $md5cr;	# last crypt item
local (*READ1,*WRITE1,*READ2,*WRITE2);

my %method = (
	$crypt	=> 'new_rc4',
	$md5cr	=> 'new_md5_rc4',
	$encode	=> 'new_crypt',
	$md5enc	=> 'new_md5_crypt',
);

my $i;
foreach $i ( 0..$#v ) {
  my $failed;
  my $buff;
  my $c;
  my $binfile;

  for ( $crypt,$md5cr,$encode,$md5enc ) {
    $failed = 0;
    my $strcf	= undef;		# will be crypted text file
    my $strcIO	= undef;		# will be IO crypted text
    my $strdf	= undef;		# will be decrypted text
    my $strdIO	= undef;		# will be IO decrypted text

    if ( $module =~ /LockTite/ || $_ <= $lastcrypt ) {
# Open text file, fetch contents and encrypt
      open(READ1,$v[$i]->[$file]) || die "Can't open $v[$i]->[$file]: $!";
      while (read(*READ1,$buff,4096)) {
	$strcf .= $buff;
      }
      close *READ1;
      ($c,$binfile)  = &new_method ($_,$i,$file);
      $strcf = $c->encrypt($strcf);

# Open text file, use IO encrypt
      open(READ1,$v[$i]->[$file]) || die "Can't open $v[$i]->[$file]: $!";
      if ( $usepipes ) {
	(*READ2,*WRITE2) = &child2pipe('R2','W2');
      } else {
	*WRITE2 = &write_fh('W2',$fa);
      }
      ($c,$binfile)  = &new_method ($_,$i,$file);
      $c->encrypt_fileIO(*READ1,*WRITE2);
      close READ1;
      close *WRITE2;
      *READ2 = &read_fh('R2',$fa) unless $usepipes;
      while (read(*READ2,$buff,4096)) {
	$strcIO .= $buff;
      }
      close *READ2;

      if ( $strcf ne $strcIO ) {
	print "failed string crypt ne fileIO crypt $v[$i]->[$file]\n";
	++$failed;
      }

# Check MD5 of crypt string against expected
      $c = new_md5 $module;
      $c = $c->md5_hex($strcIO);
      if ( $c ne $v[$i]->[$_] ) {
	print "MD5 crypt failed on crypt $v[$i]->[$file]\n" .
	"got $c, expected $v[$i]->[$_]\n";
	++$failed;
      }

###################### phase 2
# Build coded file if encrypt
      if ( $_ > $lastcrypt ) {
	open(READ1,$v[$i]->[$file]) || die "Can't open $v[$i]->[$file]: $!";
	($c,$binfile)  = &new_method ($_,$i,$file);
	open(WRITE1,">$binfile") || die "Can't open $binfile: $!";
	$c->encrypt_fileIO(*READ1,*WRITE1);
	close *READ1;
	close *WRITE1;
# Open input file stream for dcrypt in next test
	open(READ1,$binfile) || die "Can't open $binfile: $!";
# NOTE: READ1 is open!
      }
	else {
# Build input stream for dcrypt in next test
	if ( $usepipes ) {
	  (*READ1,*WRITE1) = &child2pipe('R1','W1');
	} else {
	  *WRITE1 = &write_fh('W1',$fb);
	}
	select *WRITE1;
	$| = 1;
	print $strcIO;
	select STDOUT;
	close *WRITE1;
	*READ1 = &read_fh('R1',$fb) unless $usepipes;
# NOTE: READ1 is open!
      }

    } else {	# NOT = LockTite -- read only, use test file
      ($c,$binfile)  = &new_method ($_,$i,$file);
# Open input file stream for dcrypt in next test
      open(READ1,$binfile) || die "Can't open $binfile: $!";
# NOTE: READ1 is open!
    }
###################### phase 3
# READ1 is the file handle for the crypted stream
    if ( $usepipes ) {
      (*READ2,*WRITE2) = &child2pipe('R2','W2');
    } else {
      *WRITE2 = &write_fh('W2',$fa);
    }
    ($c,$binfile)  = &new_method ($_,$i,$file);
    $c->crypt_fileIO(*READ1,*WRITE2);
    close *READ1;
    close *WRITE2;
    *READ2 = &read_fh('R2',$fa) unless $usepipes;
    while (read(*READ2,$buff,4096)) {
      $strdIO .= $buff;		# decrypted string
    }
    close *READ2;

# GET text file for comparison
    open(READ1,$v[$i]->[$file]) || die "Can't open $v[$i]->[$file]: $!";
    while(read(*READ1,$buff,4096)) {
      $strdf .= $buff;
    }
    close *READ1;

    if ( $strdf ne $strdIO ) {
      print "decrypted string ne text file\n";
      ++$failed;
    }

    print 'not ' if $failed;
    print "ok $testno\n";
    ++$testno;
  }
}
unlink ($fa, $fb) unless $usepipes;

sub new_method {
  my ($mode, $i,$f) = @_;
  my $c = ($mode == $md5enc) ? '.md5.bin' : '.bin';	# harmless if 'crypt or md5_crypt'
  $f = "$v[$i]->[$file]${c}";
#print 'file=', $f,"\n",'meth=',$method{$mode},"\n";
  $c = eval qq|$method{$mode} ${module}('password',"$f")|;
  return ($c, $f);
}

sub childtimeout {
  exit;
}

sub read_fh {
  local (*READ,$tf) = @_;
  open(*READ,$tf) or die "Can't open $tf: $!";
  return *READ;
}

sub write_fh {
  local(*WRITE,$tf) = @_;
  open(*WRITE,">$tf") or die "Can't open $tf: $!";
  return *WRITE;
}

sub child2pipe {
  my ($R,$W) = @_;
  local(*ReadFromChild,*WriteToChild);
  $ReadFromChild	= $R . 'fc';
  $WriteToParent	= $W . '2p';
  $ReadFromParent	= $R . 'fp';
  $WriteToChild		= $W . '2c';

  pipe(*ReadFromChild,*WriteToParent);
  pipe(*ReadFromParent,*WriteToChild);

  my $pid;
  unless ($pid = fork) {
    unless (fork) {
      close *ReadFromChild;
      close *WriteToChild;
      my $savA = $SIG{'ALRM'};
#      $SIG{'ALRM'} = 'childtimeout';
#      alarm 60;
      my $buff;
      my $out = undef;
      while (read(*ReadFromParent,$buff,1024)) {
        $out .= $buff;
      }
      select *WriteToParent;
      $| = 1;
      print $out;
      select STDOUT;
#      alarm 0;
#      $SIG{'ALRM'} = $savA || undef;
      exit 0;
    }
    exit 0;
  }
  close *ReadFromParent;
  close *WriteToParent;
  waitpid($pid,0);
  return(*ReadFromChild,*WriteToChild);
}

