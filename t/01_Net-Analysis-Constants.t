# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl NetPacket2-Utils.t'
# $Id$

use strict;
use warnings;

use Test::More tests => 2;

#########################

BEGIN { use_ok('Net::Analysis::Constants') };

# This is a bit pathetic, really.
use Net::Analysis::Constants qw(:all);
isnt (URG, undef, "URG is defined");

__END__
