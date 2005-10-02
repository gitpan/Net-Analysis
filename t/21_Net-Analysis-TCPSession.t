# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Net::Analysis-Utils.t'

use strict;
use Data::Dumper;

use Test::More tests => 10;
use t::TestFileIntoPackets;
use t::TestEtherealGlue;

#########################

BEGIN { use_ok('Net::Analysis::TCPSession') };

####

use Net::Analysis::TCPSession qw(:const); # Get the constants
use Net::Analysis::Constants  qw(:tcpseshstates :packetclasses);

#### Check the constructor constructs ...
#
my $sesh = Net::Analysis::TCPSession->new();
isnt ($sesh, undef, "TCPSession->new()");


#### Just check we can read packets etc.
#
my (@pkts) = @{tcpfile_into_packets ("t/t1_google.tcp")};
is (scalar(@pkts), 11, 'read in 11 packets from t1_google');


#### Test that the session moves between states correctly.
#
my (@found);
my (@expected) = (# sesh->status(),  ret of process_packet()
                  [SESH_CONNECTING,  PKT_OK],
                  [SESH_CONNECTING,  PKT_OK],
                  [SESH_ESTABLISHED, PKT_ESTABLISHED_SESSION],
                  [SESH_ESTABLISHED, PKT_OK],
                  [SESH_ESTABLISHED, PKT_FLIPPED_DIR], #pkt 4
                  [SESH_ESTABLISHED, PKT_OK],
                  [SESH_ESTABLISHED, PKT_OK],
                  [SESH_ESTABLISHED, PKT_OK],
                  [SESH_ESTABLISHED, PKT_OK],
                  [SESH_HALF_CLOSED, PKT_OK],
                  [SESH_CLOSED,      PKT_TERMINATED_SESSION]
                 );

foreach my $pkt (@pkts) {
    my $ret = $sesh->process_packet (packet => $pkt);
    #printf "%-90.90s [%-2.2s] %s\n", "$pkt", $ret, "$sesh";
    push (@found, [$sesh->status(), $ret]);
}
is_deeply (\@found, \@expected, "session status is correct");


#### Test that our session sets packet states correctly.
#
# This mess done by inspection of packet trace.
# Really need some data dups too :/
#
($sesh, @found) = ( $sesh = Net::Analysis::TCPSession->new(), () );

@expected = (PKT_NONDATA) x 65;
@expected[4,6,8,10,12,14,16,18,20,22,24,26,28,30,32,34,36, # *Not 38 !
          40,42,44,46,48,50,52,54,56,58,60,62] = (PKT_DATA) x 29;
$expected[38] = (PKT_FUTURE_DATA);
foreach my $pkt ( @{tcpfile_into_packets ("t/t3_data_resend.tcp")} ) {
    $sesh->process_packet (packet => $pkt);
    #printf "%-90.90s %s\n", "$pkt", '';#"$sesh";
    push (@found, $pkt->class());
}
is_deeply (\@found, \@expected, "packet classes are correct");



#### Now run over all our testfiles, building monologues
#
test_monologues($_) for (list_testfiles());

######## Support Functions #########

sub test_monologues {
    my ($t) = @_;
    my $actual_mono = hexdump_to_monologues ("t/$t.hex");
    my $mono = get_monologues ($t);

    if (1) {
        is_deeply ($mono, $actual_mono, "test '$t': (".
                   scalar(@$mono)." monologues) reassembled OK");

    } else {
        # More useful debugging ...
        for my $i (0..$#$mono) {
            printf "actual: % 6.6d, found: % 6.6d\n", length($actual_mono->[$i]),
                length($mono->[$i]);
            if (open (OUT1, ">$t.$i.in")) { print OUT1 $actual_mono->[$i] }
            if (open (OUT2, ">$t.$i.out")) { print OUT2 $mono->[$i] }
        }
    }
}

sub get_monologues {
    my ($test_name) = @_;
    my ($D) = 0;

    my (@pkts) = @{tcpfile_into_packets ("t/$test_name.tcp")};
    #is (scalar(@pkts), 11, 'read in 11 packets from $test_name');

    my $sesh = Net::Analysis::TCPSession->new ();

    my (@mono);
    foreach my $pkt (@pkts) {
        my $ret = $sesh->process_packet (packet => $pkt);
        ($ret == PKT_REJECTED) && die "logical failure: ".$sesh->errstr();
        if ($ret == PKT_FLIPPED_DIR) {
            push (@mono, $sesh->previous_monologue()->{data});
        }
        printf "%-100.100s %s\n", "$pkt", "$sesh" if ($D);
    }

    if ($sesh->has_current_monologue()) {
        push (@mono, $sesh->current_monologue()->{data});
    }

    return \@mono;
}

__DATA__
