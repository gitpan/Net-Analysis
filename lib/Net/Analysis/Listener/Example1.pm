package Net::Analysis::Listener::Example1;
# $Id: Example1.pm 136 2005-10-21 00:14:54Z abworrall $

# This Listener simply looks at monologues, and (somewhat needlessly) emits
#  and then catches an event to display some bandwidth info.

use strict;
use warnings;
use base qw(Net::Analysis::Listener::Base);

sub tcp_monologue {
    my ($self, $args) = @_;
    my ($mono) = $args->{monologue};

    my $t = $mono->t_elapsed()->as_number();
    my $l = $mono->length();

    $self->emit(name => 'example_bandwidth_measurement_event',
                args => { kb_sec => ($t) ? $l/($t*1024) : 0 }
               );
}

sub example_bandwidth_measurement_event {
    my ($self, $args) = @_;

    printf "Bandwidth: %10.2f KB/sec\n", $args->{kb_sec};
}

1;
