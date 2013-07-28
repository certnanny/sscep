#!perl -w

use strict;
use diagnostics;
use Test::More;

plan tests => 1;

TODO: {
  local $TODO = "Not yet implemented.";
  fail("dummy");
}

# if there are serious problems:
BAIL_OUT("Aborting test...");

