package Net::Analysis::Listener::Example;
# $Id: Example.pm 131 2005-10-02 17:24:31Z abworrall $

use strict;
use warnings;
use base qw(Net::Analysis::Listener::Base);

sub tcp_monologue {
    my ($self, $args) = @_;
    my ($mono) = $args->{monologue};

    my $t = $mono->t_elapsed()->as_number();
    my $l = $mono->length();

    $self->emit(name => 'example_event',
                args => { kb_sec => ($t) ? $l/($t*1024) : 'N/A' }
               );
}

sub example_event {
    my ($self, $args) = @_;

    printf "Bandwidth: %10.2f KB/sec\n", $args->{kb_sec};
}

1;
