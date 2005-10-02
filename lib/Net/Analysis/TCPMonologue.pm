package Net::Analysis::TCPMonologue;
# $Id: TCPMonologue.pm 131 2005-10-02 17:24:31Z abworrall $

use 5.008000;
our $VERSION = '0.01';
use strict;
use warnings;

use overload
    q("") => sub { $_[0]->as_string() },
    'eq'  => sub { return "$_[0]" eq "$_[1]" }; # Needed for Test::is_deeply

use Carp qw(carp croak confess);
use Params::Validate qw(:all);

# {{{ POD

=head1 NAME

Net::Analysis::TCPMonologue - simple class to contain a TCP monologue

=head1 SYNOPSIS

  use Net::Analysis::Packet;
  use Net::Analysis::Monologue;

  my $mono = Net::Analysis::Monologue->new();
  $mono->add_packet($pkt);

  print "Monologue was " .$mono->length().
        "b long, over "  .$mono->t_elapsed ()." seconds\n";

=head1 DESCRIPTION

A TCP monologue is a series of packets that travel in one direction, e.g. a
HTTP response. A monologue ends when a data packet travels in the other
direction. Pairs of monologues will often be linked as transactions.

As packets are added, this object updates some info. It assumes that the packet
you've added belongs in the monologue, and that you're adding them in the
correct order.

The payload of the monologue lives in C<$mono->{data}>.

=head1 METHODS

=cut

# }}}

#### Public methods
#
# {{{ new

# {{{ POD

=head2 new ( )

Takes no arguments.

=cut

# }}}

sub new {
    my ($class) = shift;

    my %h; # = validate (@_, {});

    my ($self) = bless ({}, $class);

    return $self;
}

# }}}
# {{{ add_packet

=head2 add_packet ($pkt)

Adds any data, increments the packet counter, and keeps note of the time.

=cut

sub add_packet {
    my ($self, $pkt) = @_;

    if (!exists $self->{data}) {
        # No data ? Must be the first packet; trigger some init
        $self->_init_from_first_packet($pkt);
    }

    $self->{n_packets}++;
    $self->{data} .= $pkt->{data};

    # Now update the 'last packet' time counters
    if ($pkt->{time} > $self->{time}) {
        $self->{time}  = $pkt->{time};
    }

    #print "Adding packet $pkt to $self\n";

    return 1;
}

# }}}

# {{{ t_start

=head2 t_start ()

Returns an object representing the time the monologue started. Can be treated
like a float, giving fractional epoch seconds. Only accurate to the
microsecond.

=cut

sub t_start {
    my ($self) = @_;
    return $self->{t_start};
}

# }}}
# {{{ t_end

=head2 t_end ()

Same as C<t_start()>, but giving the time the monologue ended (or the last
packet so far, if you call it before the monologue has ended.)

=cut

sub t_end {
    my ($self) = @_;
    return $self->{time};
}

# }}}
# {{{ t_elapsed

=head2 t_elapsed ()

Returns an object representing C<t_end - t_start> for this monologue. Can be
treated like a float, giving duration in fractional seconds.

=cut

sub t_elapsed {
    my ($self) = @_;
    return ($self->{time} - $self->{t_start});
}

# }}}
# {{{ n_packets

=head2 n_packets ()

How many data packets were in the monologue.

=cut

sub n_packets {
    my ($self) = @_;
    return ($self->{n_packets});
}

# }}}
# {{{ length

=head2 length ()

How long the monologue data was, in bytes. Excludes all the various packet
headers.

=cut

sub length {
    my ($self) = @_;
    return length($self->{data});
}

# }}}

# {{{ as_string

sub as_string {
    my ($self) = @_;
    my $str = '';

    if (exists $self->{data}) {
        my $dur = $self->t_elapsed();
        $str .= sprintf ("[Mono from %21.21s]%10.06fs, %3dpkts, %6db",
                         $self->{from}, $dur, $self->n_packets(),
                         $self->length());
    } else {
        $str .= "[Mono undefined]";
    }

    return $str;
}

# }}}


#### Private helper methods
#
# {{{ _init_from_first_packet

sub _init_from_first_packet {
    my ($self, $pkt) = @_;

    $self->{n_packets} = 0;
    $self->{data}      = '';

    # Initialise the monologue
    for (qw(to from)) {
        $self->{$_} = $pkt->{$_};
    }
    $self->{time} = $pkt->{time} + 0; # Make a cloned copy

    # Keep copies of the first ever time.
    $self->{t_start}  = $self->{time};
}

# }}}

1;
__END__
# {{{ POD

=head2 EXPORT

None by default.

=head1 AUTHOR

Adam B. Worrall, E<lt>worrall@cpan.orgE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2004 by Adam B. Worrall

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.5 or,
at your option, any later version of Perl 5 you may have available.

=cut

# }}}

# {{{ -------------------------={ E N D }=----------------------------------

# Local variables:
# folded-file: t
# end:

# }}}
