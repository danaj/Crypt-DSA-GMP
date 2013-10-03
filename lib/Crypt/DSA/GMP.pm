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
    my $dsa = shift;
    my %param = @_;
    my($key, $dgst);
    croak __PACKAGE__, "->sign: Need a Key" unless $key = $param{Key};
    unless ($dgst = $param{Digest}) {
        croak __PACKAGE__, "->sign: Need either Message or Digest"
            unless $param{Message};
        # Determine which standard we're following.
        $param{Standard} = $dsa->{Standard}
          if defined $dsa->{Standard} && !defined $param{Standard};
        if (defined $param{Standard} && $param{Standard} =~ /186-[34]/) {
          # TODO: SP 800-57 rev 3 indicates we need to look at bitsize(q)
          # and use a stronger hash.
          $dgst = sha256($param{Message});
        } else {
          $dgst = sha1($param{Message});
        }
    }

    # FIPS 186-4, section 4.6 "DSA Signature Generation"
    my ($p, $q, $g) = ($key->p, $key->q, $key->g);

    # compute z as the leftmost MIN(N, outlen) bits of the digest
    my $z = bin2mp($dgst);
    my ($N, $outlen) = ( bitsize($q), 8*length($dgst) );
    $z->brsft($outlen - $N) if $outlen > $N;

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
    my $dsa = shift;
    my %param = @_;
    my($key, $dgst, $sig);
    croak __PACKAGE__, "->verify: Need a Key" unless $key = $param{Key};
    unless ($dgst = $param{Digest}) {
        croak __PACKAGE__, "->verify: Need either Message or Digest"
            unless $param{Message};
        # Determine which standard we're following.
        $param{Standard} = $dsa->{Standard}
          if defined $dsa->{Standard} && !defined $param{Standard};
        if (defined $param{Standard} && $param{Standard} =~ /186-[34]/) {
          $dgst = sha256($param{Message});
        } else {
          $dgst = sha1($param{Message});
        }
    }
    croak __PACKAGE__, "->verify: Need a Signature"
        unless $sig = $param{Signature};

    my ($p, $q, $r, $s) = ($key->p, $key->q, $sig->r, $sig->s);
    return 0 unless $r > 0 && $r < $q;
    return 0 unless $s > 0 && $s < $q;
    my $w = mod_inverse($s, $q);
    $dgst = substr($dgst, 0, int((bitsize($q+7)/8)))
        if 8*length($dgst) > bitsize($q);
    my $z = bin2mp($dgst);
    my $u1 = $w->copy->bmul($z)->bmod($q);
    my $u2 = $w->copy->bmul($r)->bmod($q);
    my $v =        mod_exp($key->g,       $u1, $p)
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

I<Crypt::DSA::GMP> is an implementation of the DSA (Digital Signature
Algorithm) signature verification system. The implementation
itself is pure Perl, although the heavy-duty mathematics underneath
are provided by the L<Math::BigInt::GMP> and
L<Math::Prime::Util::GMP> modules.

This package provides DSA signing, signature verification, and key
generation.

=head1 USAGE

The I<Crypt::DSA::GMP> public interface is similar to that of
I<Crypt::RSA>. This was done intentionally.

=head2 Crypt::DSA->new

Constructs a new I<Crypt::DSA> object. At the moment this isn't
particularly useful in itself, other than being the object you
need to do much else in the system.

Returns the new object.

=head2 $key = $dsa->keygen(%arg)

Generates a new set of DSA keys, including both the public and
private portions of the key.

I<%arg> can contain:

=over 4

=item * Size

The size in bits of the I<p> value to generate.  The I<q> value
will be 160 bits if Size is less than 2048, 256 bits otherwise.
The size in bits of I<g> is always less than or equal to Size.

This argument is mandatory, and must be at least 256.

=item * Seed

A seed with which I<q> generation will begin. If this seed does
not lead to a suitable prime, it will be discarded, and a new
random seed chosen in its place, until a suitable prime can be
found.

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

The return value--the signature--is a I<Crypt::DSA::GMP::Signature>
object.

I<%arg> can include:

=over 4

=item * Digest

A digest to be signed. The digest should be 20 bytes in length
or less.

You must provide either this argument or I<Message> (see below).

=item * Key

The I<Crypt::DSA::GMP::Key> object with which the signature will be
generated. Should contain a private key attribute (I<priv_key>).

This argument is required.

=item * Message

A plaintext message to be signed. If you provide this argument,
I<sign> will first produce a SHA1 digest of the plaintext, then
use that as the digest to sign. Thus writing

    my $sign = $dsa->sign(Message => $message, ... );

is a shorter way of writing

    use Digest::SHA1 qw( sha1 );
    my $sig = $dsa->sign(Digest => sha1( $message ), ... );

=back

=head2 $verified = $dsa->verify(%arg)

Verifies a signature generated with I<sign>. Returns a true
value on success and false on failure.

I<%arg> can contain:

=over 4

=item * Key

Key of the signer of the message; a I<Crypt::DSA::GMP::Key> object.
The public portion of the key is used to verify the signature.

This argument is required.

=item * Signature

The signature itself. Should be in the same format as returned
from I<sign>, a I<Crypt::DSA::GMP::Signature> object.

This argument is required.

=item * Digest

The original signed digest whose length is less than or equal to
20 bytes.

Either this argument or I<Message> (see below) must be present.

=item * Message

As above in I<sign>, the plaintext message that was signed, a
string of arbitrary length. A SHA1 digest of this message will
be created and used in the verification process.

=back

=head1 TODO

Add ability to munge format of keys. For example, read/write keys
from/to key files (SSH key files, etc.), and also write them in
other formats.

Crypt::DSA was written from the old SHA1-based standards, and it
is the intention of Crypt::DSA::GMP to support the newer standards.
NIST withdrew the old Crypt::DSA methods on June 2009.
The trick is doing this while remaining backward compatible.

=head1 SUPPORT

Bugs should be reported via the CPAN bug tracker at

L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Crypt-DSA>

For other issues, contact the author.

=head1 AUTHOR

Benjamin Trott E<lt>ben@sixapart.comE<gt>

=head1 COPYRIGHT

Except where otherwise noted,
Crypt::DSA is Copyright 2006 - 2011 Benjamin Trott.

Crypt::DSA is free software; you may redistribute it
and/or modify it under the same terms as Perl itself.

=cut
