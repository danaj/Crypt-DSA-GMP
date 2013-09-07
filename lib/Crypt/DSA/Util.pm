package Crypt::DSA::Util;
use warnings;
use strict;
use Math::BigInt lib => "GMP";
use Crypt::Random::Seed;
use Digest::SHA qw/sha1_hex/;
use Carp qw( croak );

use vars qw( $VERSION @ISA @EXPORT_OK );
use Exporter;
BEGIN {
    $VERSION   = '1.17';
    @ISA       = qw( Exporter );
    @EXPORT_OK = qw( bitsize bin2mp mp2bin mod_inverse mod_exp makerandom randombytes sha1random );
}

sub bitsize {
  my $n = shift;
  $n = Math::BigInt->new("$n") unless ref($n) eq 'Math::BigInt';
  length($n->as_bin) - 2;
}

# This is the os2ip function
sub bin2mp {
    my $s = shift;
    return Math::BigInt->new(0) if !defined $s || $s eq '';
    return Math::BigInt->from_hex(unpack("H*", $s));
}

# This is the i2osp function
sub mp2bin {
    my $p = shift;
    my $res = '';
    if (ref($p) ne 'Math::BigInt' && $p <= ~0) {
      do {
        $res = chr($p & 0xFF) . $res;
        $p >>= 8;
      } while $p;
    } else {
      $p = Math::BigInt->new("$p") unless ref($p) eq 'Math::BigInt';
      my $hex = $p->as_hex;
      $hex =~ s/^0x0*//;
      substr($hex, 0, 0, '0') if length($hex) % 2;
      $res = pack("H*", $hex);
    }
    $res;
}

sub mod_exp {
    my($a, $exp, $n) = @_;
    $a->copy->bmodpow($exp, $n);
}

sub mod_inverse {
    my($a, $n) = @_;
    $a->copy->bmodinv($n);
}

# Easy method using BRS:
# sub randombytes {
#   return Bytes::Random::Secure::random_bytes(@_);
# }
{
  my $crs_source = undef;
  sub randombytes {
    $crs_source = Crypt::Random::Seed->new() unless defined $crs_source;
    return $crs_source->random_bytes(@_);
  }
}

sub makerandom {
    my %param = @_;
    my $size = $param{Size};
    my $bytes = int($size / 8) + 1;

    my $r = randombytes($bytes);
    my $down = $size - 1;
    $r = unpack 'H*', pack 'B*', '0' x ( $size % 8 ? 8 - $size % 8 : 0 ) .
        '1' . unpack "b$down", $r;
    Math::BigInt->new('0x' . $r);
}

1;
__END__

=head1 NAME

Crypt::DSA::Util - DSA Utility functions

=head1 SYNOPSIS

    use Crypt::DSA::Util qw( func1 func2 ... );

=head1 DESCRIPTION

I<Crypt::DSA::Util> contains a set of exportable utility functions
used through the I<Crypt::DSA> set of libraries.

=head2 bitsize($n)

Returns the number of bits in the I<Math::Pari> integer object
I<$n>.

=head2 bin2mp($string)

Given a string I<$string> of any length, treats the string as a
base-256 representation of an integer, and returns that integer,
a I<Math::Pari> object.

=head2 mp2bin($int)

Given a biginteger I<$int> (a I<Math::Pari> object), linearizes
the integer into an octet string, and returns the octet string.

=head2 mod_exp($a, $exp, $n)

Computes $a ^ $exp mod $n and returns the value. The calculations
are done using I<Math::Pari>, and the return value is a I<Math::Pari>
object.

=head2 mod_inverse($a, $n)

Computes the multiplicative inverse of $a mod $n and returns the
value. The calculations are done using I<Math::Pari>, and the
return value is a I<Math::Pari> object.

=head1 AUTHOR & COPYRIGHTS

Please see the Crypt::DSA manpage for author, copyright,
and license information.

=cut
