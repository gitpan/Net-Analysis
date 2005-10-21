package Net::Analysis::Listener::Example2;
# $Id: Example.pm 131 2005-10-02 17:24:31Z abworrall $

# This Listener prints a brief summary of the monologue traffic, and
#  optionally greps the monologue data for a regex, if one is passed
#  via config into $self.

use strict;
use warnings;
use base qw(Net::Analysis::Listener::Base);

sub tcp_monologue {
    my ($self, $args) = @_;
    my ($mono) = $args->{monologue};
    my ($pkt)  = $mono->first_packet();
    my ($from) = $pkt->{from};
    my ($time) = $pkt->{time}->as_string('full');

    printf "(%s)  %-22.22s % 6d bytes", $time, $from, $mono->length();

    if ($mono->data() =~ /(.{0,10}$self->{regex}.{0,10})/i) {
        print " ** regex matched: '$1'";
    }

    print "\n";
}

1;
