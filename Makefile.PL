use ExtUtils::MakeMaker;

# change the file name below to alter the target file
#
# to generate Crypt::somefilename
#
# Any file containing the string "LockTite" will include the 
# proprietary "encode" function, other wise it is disabled
#
# using the command line NAME=something WILL NOT WORK!!!
#####################################################
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

my $NAME = (1)		# set to 1 for CapnMidnite, false for C_Locktite
	? 'CapnMidNite'
	: 'C_LockTite';

open (N,'>'.name) or die "could not open config file 'name'\n";
print N q|$module = Crypt::| . $NAME . "\n";
close N;

my $pm_module = 'My_Module_PM';
my $xs_source = 'Source_XS';

sub MY::top_targets {
  package MY;	# add dependencies for .pm and xs files
  my $inherited = "
#Added for Crypt
$NAME.pm : $pm_module
	./makePMsource $NAME $pm_module

$NAME.xs : $xs_source
	./makeXSsource $NAME $xs_source

all :: $NAME.pm $NAME.xs

" . shift->SUPER::top_targets(@_);
}

WriteMakefile(
    'NAME'		=> "Crypt::$NAME",
    'VERSION_FROM'	=> "$pm_module", # finds $VERSION
    'XSPROTOARG'	=> '-noprototypes',
    'PM'		=> { "$NAME.pm"	=> "\$(INST_LIBDIR)/$NAME.pm"},
    'clean'		=> {FILES	=> "$NAME.c *.xs *.pm *.bs"},
    'OBJECT'		=> "$NAME.o md5.o rc4.o",
    'TYPEMAPS'		=> ['perlobject.map' ],
    'dist'		=> {COMPRESS=>'gzip', SUFFIX=>'gz'}
);
