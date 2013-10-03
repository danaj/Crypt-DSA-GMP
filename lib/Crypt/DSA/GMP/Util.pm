package Crypt::DSA::GMP::Util;
use strict;
use warnings;

BEGIN {
  $Crypt::DSA::GMP::Util::AUTHORITY = 'cpan:DANAJ';
  $Crypt::DSA::GMP::Util::VERSION = '0.01';
}

use Carp qw( croak );
use Math::BigInt lib => "GMP";
use Crypt::Random::Seed;
use Digest::SHA qw/sha1_hex/;

use base qw( Exporter );
our @EXPORT_OK = qw( bitsize bin2mp mp2bin mod_inverse mod_exp makerandom randombytes sha1random );
our %EXPORT_TAGS = (all => [ @EXPORT_OK ]);

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
    $crs_source = Crypt::Random::Seed->new(NonBlocking=>1)
      unless defined $crs_source;
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

Crypt::DSA::GMP::Util - DSA Utility functions

=head1 SYNOPSIS

    use Crypt::DSA::GMP::Util qw( func1 func2 ... );

=head1 DESCRIPTION

I<Crypt::DSA::GMP::Util> contains a set of exportable utility functions
used through the I<Crypt::DSA::GMP> set of libraries.

=head2 bitsize($n)

Returns the number of bits in the integer I<$n>.

=head2 bin2mp($string)

Given a string I<$string> of any length, treats the string as a
base-256 representation of an integer, and returns that integer

=head2 mp2bin($int)

Given an integer I<$int> (maybe a L<Math::BigInt> object), linearizes
the integer into an octet string, and returns the octet string.

=head2 mod_exp($a, $exp, $n)

Computes $a ^ $exp mod $n and returns the value.

=head2 mod_inverse($a, $n)

Computes the multiplicative inverse of $a mod $n and returns the
value.

=head1 AUTHOR & COPYRIGHTS

See L<Crypt::DSA::GMP> for author, copyright, and license information.

=cut
