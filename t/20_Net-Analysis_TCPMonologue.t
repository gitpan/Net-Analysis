# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Net::Analysis-Utils.t'

use strict;
use Data::Dumper;

use Test::More tests => 14;
use t::TestFileIntoPackets;

#########################

BEGIN { use_ok('Net::Analysis::TCPMonologue') };


# Just check we can read packets etc.
my (@pkts) = @{tcpfile_into_packets ("t/t1_google.tcp")};
is (scalar(@pkts), 11, 'read in 11 packets from t1_google');

# Packets 4 and 6 form a short monologue. Test with them.

# Check the constructor constructs ...
my $mono = Net::Analysis::TCPMonologue->new();
isnt ($mono, undef, "TCPSession->new()");
is ("$mono", '[Mono undefined]', 'initial mono');

# Add the packets, and lazily brittle test via string_as() output ...
is ($mono->add_packet($pkts[4]), 1, 'packet added OK');
is ("$mono", '[Mono from     216.239.59.147:80]  0.000000s,   1pkts,   1368b',
    'mono, first packet');

is ($mono->add_packet($pkts[6]), 1, 'packet added OK');
is ("$mono", '[Mono from     216.239.59.147:80]  0.000069s,   2pkts,   2245b',
    'mono, second packet');

# Ensure accuracy of the time things
is (sprintf ("%017.6f", $mono->t_start()),  '1096989582.739317', 't_start');
is (sprintf ("%017.6f", $mono->t_end()),    '1096989582.739386', 't_end');
is (sprintf ("%017.6f", $mono->t_elapsed()),'0000000000.000069', 't_elapsed');


# Misc observers
is ($mono->n_packets(),    2, 'n_packets');
is ($mono->length(),    2245, 'length');
is_deeply ($mono->first_packet(), $pkts[4], 'first_packet');

__DATA__
