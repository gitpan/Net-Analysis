package t::TestFileIntoPackets;
# $Id: TestFileIntoPackets.pm 131 2005-10-02 17:24:31Z abworrall $

# Provides some routines used in various tests ...

use 5.008000;
our $VERSION = '0.01';
use strict;
use warnings;
use Carp qw(carp croak confess);

require Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw(tcpfile_into_packets);

use t::TestMockListener;
use Net::Analysis::EventLoop;
use Net::Analysis::Dispatcher;
use Net::Analysis::Packet;

#### Turn a TCP file into an array of our packets
#
sub tcpfile_into_packets {
    my ($fname) = @_;
    my (@pkts, $event_name, @args);

    my ($d) = Net::Analysis::Dispatcher->new();
    my ($l) = mock_listener('tcp_packet');
    $d->add_listener (listener => $l);

    my ($el) = Net::Analysis::EventLoop->new (dispatcher => $d);
    $el->loop_file (filename => $fname);

    while (($event_name, @args) = $l->next_call()) {
        next if ($event_name ne 'tcp_packet');
        push (@pkts, $args[0][1]{pkt});
    }

    return \@pkts;
}


1;
