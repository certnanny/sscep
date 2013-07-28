#!perl -w

use strict;
use diagnostics;
use Test::More;

plan tests => 2;

my $output = qx(./sscep);
is($?, 0, "./sscep with arguments should have exit code 0");
like($output, qr/Usage:/i, "sscep should output usage message when run without arguments");

