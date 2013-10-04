package Crypt::DSA::GMP;
use 5.006;
use strict;
use warnings;

BEGIN {
  $Crypt::DSA::GMP::AUTHORITY = 'cpan:DANAJ';
  $Crypt::DSA::GMP::VERSION = '0.01';
}

use Carp qw( croak );
use Math::BigInt lib => "GMP";
use Digest::SHA qw( sha1 sha256 sha512 );
use Crypt::DSA::GMP::KeyChain;
use Crypt::DSA::GMP::Key;
use Crypt::DSA::GMP::Signature;
use Crypt::DSA::GMP::Util qw( bitsize bin2mp mod_inverse mod_exp makerandomrange );

sub new {
    my $class = shift;
    my $dsa = bless { @_ }, $class;
    $dsa->{_keychain} = Crypt::DSA::GMP::KeyChain->new(@_);
    $dsa;
}

sub keygen {
    my $dsa = shift;
    my $key = $dsa->{_keychain}->generate_params(@_);
    $dsa->{_keychain}->generate_keys($key);
    $key;
}

sub sign {
    my ($dsa, %param) = @_;
    my ($key, $dgst) = ($param{Key}, $param{Digest});

    croak __PACKAGE__, "->sign: Need a Key" unless defined $key && ref($key);
    my ($p, $q, $g) = ($key->p, $key->q, $key->g);
    my $N = bitsize($q);

    if (!defined $dgst) {
        my $message = $param{Message};
        croak __PACKAGE__, "->sign: Need either Message or Digest"
            unless defined $message;
        # Determine which standard we're following.
        $param{Standard} = $dsa->{Standard}
          if defined $dsa->{Standard} && !defined $param{Standard};
        if (defined $param{Standard} && $param{Standard} =~ /186-[34]/) {
          # See NIST SP 800-57 revision 3, section 5.6.1
          $dgst = ($N > 256) ? sha512($message) : sha256($message);
        } else {
          $dgst = sha1($message);
        }
    }

    # FIPS 186-4, section 4.6 "DSA Signature Generation"

    # compute z as the leftmost MIN(N, outlen) bits of the digest
    my $z = bin2mp($dgst);
    $z->brsft(8*length($dgst) - $N) if $N < 8*length($dgst);

    # Generate r and s, ensuring neither are zero.
    my ($r, $s);
    do {
      my ($k, $kinv);
      do {
        # k is per-message random number 0 < k < q
        $k = makerandomrange( $q-2 ) + 1;
        $r = mod_exp($g, $k, $p)->bmod($q);
      } while $r == 0;
      $kinv = mod_inverse($k, $q);
      $s = ($kinv * ($z + $key->priv_key * $r)) % $q;
    } while $s == 0;
    croak "Internal error in signing" if $r == 0 || $s == 0;

    my $sig = Crypt::DSA::GMP::Signature->new;
    $sig->r($r);
    $sig->s($s);
    $sig;
}

sub verify {
    my ($dsa, %param) = @_;
    my ($key, $dgst, $sig) = ($param{Key}, $param{Digest}, $param{Signature});

    croak __PACKAGE__, "->verify: Need a Key"
        unless defined $key && ref($key);
    croak __PACKAGE__, "->verify: Need a Signature"
        unless defined $sig && ref($sig);
    my ($p, $q, $g, $r, $s) = ($key->p, $key->q, $key->g, $sig->r, $sig->s);
    return 0 unless $r > 0 && $r < $q  &&  $s > 0 && $s < $q;
    my $N = bitsize($q);

    if (!defined $dgst) {
        my $message = $param{Message};
        croak __PACKAGE__, "->verify: Need either Message or Digest"
            unless defined $message;
        # Determine which standard we're following.
        $param{Standard} = $dsa->{Standard}
          if defined $dsa->{Standard} && !defined $param{Standard};
        if (defined $param{Standard} && $param{Standard} =~ /186-[34]/) {
          # See NIST SP 800-57 revision 3, section 5.6.1
          $dgst = ($N > 256) ? sha512($message) : sha256($message);
        } else {
          $dgst = sha1($message);
        }
    }

    my $w = mod_inverse($s, $q);
    my $z = bin2mp($dgst);
    $z->brsft(8*length($dgst) - $N) if $N < 8*length($dgst);
    my $u1 = $w->copy->bmul($z)->bmod($q);
    my $u2 = $w->copy->bmul($r)->bmod($q);
    my $v =        mod_exp($g,            $u1, $p)
            ->bmul(mod_exp($key->pub_key, $u2, $p))
            ->bmod($p)
            ->bmod($q);
    $v == $r;
}

1;

__END__

=pod

=head1 NAME

Crypt::DSA::GMP - DSA Signatures and Key Generation

=head1 SYNOPSIS

    use Crypt::DSA::GMP;
    my $dsa = Crypt::DSA::GMP->new;

    my $key = $dsa->keygen(
                   Size      => 512,
                   Seed      => $seed,
                   Verbosity => 1
              );

    my $sig = $dsa->sign(
                   Message   => "foo bar",
                   Key       => $key
              );

    my $verified = $dsa->verify(
                   Message   => "foo bar",
                   Signature => $sig,
                   Key       => $key,
              );

=head1 DESCRIPTION

L<Crypt::DSA::GMP> is an implementation of the DSA (Digital Signature
Algorithm) signature verification system. The implementation
itself is pure Perl, with mathematics support from
L<Math::BigInt::GMP> and L<Math::Prime::Util::GMP>.

This package provides DSA signing, signature verification, and key
generation.

This module is backwards compatible with L<Crypt::DSA>.  It removes
a number of dependencies that were portability concerns.  It
requires GMP.  Importantly, it follows FIPS 186-4 wherever
possible, and has support for the new hash methods.

=head1 USAGE

The public interface is a superset of L<Crypt::DSA>, and is
intentionally very similar to L<Crypt::RSA>.

=head2 Crypt::DSA::GMP->new

  my $dsa_2 = Crypt::DSA::GMP->new;
  my $dsa_4 = Crypt::DSA::GMP->new( Standard => "FIPS 186-4" );

Constructs and returns a new L<Crypt::DSA::GMP> object.  This
is the object used to perform other useful actions.

The standard to follow may be given in this call, where it
will be used in all methods unless overridden.  Currently
only two standards exist:

   FIPS 186-2 (includes FIPS 186-1)
   FIPS 186-4 (includes FIPS 186-3)

FIPS 186-2 is used as the default to preserve backwards
compatibility.  The primary differences:

  - NIST deprecated the old standard in 2009.

  - Crypt::DSA only supports the old standard.

  - FIPS 186-4 uses SHA-2 rather than SHA-1 for random number
    generation.  This produces better quality data.

  - FIPS 186-2 allows I<q> to be 160 bits only, where using
    FIPS 186-4 allows I<q> to be set between 1 and 512.

  - The default size for I<q> is 160 bits in all cases with
    FIPS 186-2, whereas for FIPS 186-4 it is 256 if I<Size>
    is 2048 or larger (this matches C<openssl> v1.0.1).

  - The signing and verification are done using SHA-1 for
    FIPS 186-2, whereas FIPS 186-4 applies SHA256 when I<q> is
    256 bits or smaller, and SHA512 otherwise.  Note that a
    digest may be passed in to these functions, bypassing the
    selected hashes.


=head2 $key = $dsa->keygen(%arg)

Generates a new of DSA key, including both the public and
private portions of the key.

I<%arg> can contain:

=over 4

=item * Standard

If not provided or contains C<186-1> or C<186-2> then the
backward compatible implementation is used, using SHA-1.  If it
is provided and contains C<186-3> or C<186-4> then the newer
and recommended FIPS 186-4 standard is used.

For key generation this means different default and allowed
sizes for I<q>, the use of SHA-256 or SHA-512 during random
prime generation, and the FIPS 186-4 updated prime generation
method.

The FIPS 186-4 recommended primality tests are always used as
they are more stringent than FIPS 186-2.

=item * Size

The size in bits of the I<p> value to generate.

This argument is mandatory, and must be at least 256.

=item * QSize

The size in bits of the I<q> value to generate.  This is optional.

If FIPS 186-2 is being used or I<Size> is less than 2048, then
the default value will be 160.  If FIPS 186-4 is being used and
I<Size> is 2048 or larger, then the default value is 256.

NIST SP 800-57 describes the cryptographic strengths of different
I<Size> and I<QSize> selections.  Their table 2 includes:

    Bits     L      N
    -----  -----  -----
      80    1024    160
     112    2048    224       Bits = Bits of security
     128    3072    256       L    = Size  = bit length of I<p>
     192    7680    384       N    = QSize = bit length of I<q>
     256   15360    512

In addition, if SHA-1 is used (the default without FIPS 186-4)
then the bits of security provided is strictly less than 80 bits.

=item * Seed

A seed with which I<q> generation will begin. If this seed does
not lead to a suitable prime, it will be discarded, and a new
random seed chosen in its place, until a suitable prime can be
found.

A seed that is shorter than the size of I<q> will be
immediately discarded.

This is entirely optional, and if not provided a random seed will
be generated automatically.

=item * Verbosity

Should be either 0 or 1. A value of 1 will give you a progress
meter during I<p> and I<q> generation--this can be useful, since
the process can be relatively long.

The default is 0.

=item * Prove

Should be 0, 1, I<P>, or I<Q>.  If defined and true, then both
the primes for I<p> and I<q> will have a primality proof
constructed and verified.  Setting to I<P> or I<Q> will result
in just that prime being proven.  The time for proving I<q>
should be minimal, but proving I<p> when Size is larger than
1024 can be B<very> time consuming.

The default is 0, which means the standard FIPS 186-4 probable
prime tests are done.

=back


=head2 $signature = $dsa->sign(%arg)

Signs a message (or the digest of a message) using the private
portion of the DSA key and returns the signature.

The return value (the signature) is a
I<Crypt::DSA::GMP::Signature> object.

I<%arg> can include:

=over 4

=item * Standard

If not provided or contains C<186-1> or C<186-2> then the
backward compatible implementation is used, using SHA-1.  If it
is provided and contains C<186-3> or C<186-4> then the newer
and recommended FIPS 186-4 standard is used.

For message signing this means FIPS 186-2 uses SHA-1 for digest
construction and at most 160 bits of the digest is used.  With
FIPS 186-4, SHA-256 is used if the bit length of I<q> is 256 or
less and SHA-512 is used otherwise.  If the input is a Digest
rather than a Message, then there will be no difference.

=item * Digest

A digest to be signed.  If the digest length is larger than
I<N>, the bit length of I<q>, then only the leftmost I<N> bits
will be used (as specified in FIPS 186-4).

You must provide either this argument or I<Message> (see below).

=item * Key

The I<Crypt::DSA::GMP::Key> object with which the signature will be
generated. Should contain a private key attribute (I<priv_key>).

This argument is required.

=item * Message

A plaintext message to be signed. If you provide this argument,
I<sign> will first produce a digest of the plaintext, then
use that as the digest to sign.  Thus writing

    my $sign = $dsa->sign(Message => $message, ... );

is a shorter way of writing

    # FIPS 186-2:
    use Digest::SHA qw( sha1 );
    my $sig = $dsa->sign(Digest => sha1( $message ), ... );

    # FIPS 186-4:
    use Digest::SHA qw( sha256 );
    my $sig = $dsa->sign(Digest => sha256( $message ), ... );

=back


=head2 $verified = $dsa->verify(%arg)

Verifies a signature generated with I<sign>. Returns a true
value on success and false on failure.

I<%arg> can contain:

=over 4

=item * Standard

If not provided or contains C<186-1> or C<186-2> then the
backward compatible implementation is used, using SHA-1.  If it
is provided and contains C<186-3> or C<186-4> then the newer
and recommended FIPS 186-4 standard is used.

For message verification this means FIPS 186-2 uses SHA-1
for digest construction and at most 160 bits of the digest is
used.  With FIPS 186-4, SHA-256 is used if the bit length
of I<q> is 256 or less and SHA-512 is used otherwise.  If
the input is a Digest rather than a Message, then there will
be no difference.

=item * Key

Key of the signer of the message; a I<Crypt::DSA::GMP::Key> object.
The public portion of the key is used to verify the signature.

This argument is required.

=item * Signature

The signature itself. Should be in the same format as returned
from I<sign>, a I<Crypt::DSA::GMP::Signature> object.

This argument is required.

=item * Digest

The original signed digest.  This must be computed using the
same hash that was used to sign the message.

Either this argument or I<Message> (see below) must be present.

=item * Message

As above in I<sign>, the plaintext message that was signed, a
string of arbitrary length. A digest of this message will
be created and used in the verification process.

=back


=head1 SUPPORT

Bugs should be reported via the CPAN bug tracker at

L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Crypt-DSA-GMP>

For other issues, contact the author.

=head1 AUTHORS

Dana Jacobsen E<lt>dana@acm.orgE<gt> wrote the new internals.

Benjamin Trott E<lt>ben@sixapart.comE<gt> wrote L<Crypt::DSA>
which was the basis for this module.  The PEM module remains
almost entirely his code.

=head1 COPYRIGHT

Copyright 2013 by Dana Jacobsen E<lt>dana@acm.orgE<gt>

This program is free software; you can redistribute it
and/or modify it under the same terms as Perl itself.

=cut
