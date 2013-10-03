package Crypt::DSA::GMP::KeyChain;
use strict;
use warnings;

BEGIN {
  $Crypt::DSA::GMP::KeyChain::AUTHORITY = 'cpan:DANAJ';
  $Crypt::DSA::GMP::KeyChain::VERSION = '0.01';
}

use Carp qw( croak );
use Math::BigInt lib => "GMP";
use Math::Prime::Util::GMP qw/is_prob_prime is_provable_prime miller_rabin_random/;
use Digest::SHA qw( sha1 sha1_hex);

use Crypt::DSA::GMP::Key;
use Crypt::DSA::GMP::Util qw( bin2mp bitsize mod_exp makerandom randombytes );

sub new {
    my ($class, @params) = @_;
    return bless { @params }, $class;
}

sub generate_params {
    my ($keygen, %param) = @_;
    my $bits   = int($param{Size});
    my $v      = $param{Verbosity};
    my $proveq = $param{Prove} && $param{Prove} !~ /^p$/i;
    my $provep = $param{Prove} && $param{Prove} !~ /^q$/i;
    croak "Number of bits (Size => $bits) is too small" unless $bits >= 256;

    # OpenSSL was removed to avoid portability concerns.  With the redone
    # code below plus Math::Prime::Util::GMP for primality testing, we're
    # actually faster for larger bit sizes, plus we know we're following the
    # standard we want and don't get unknown behavior.

    # Time for key generations (without proofs, average of 1000)
    #  512-bit     74ms Perl      29ms OpenSSL
    #  768-bit    108ms Perl      69ms OpenSSL
    # 1024-bit    154ms Perl     144ms OpenSSL
    # 2048-bit    832ms Perl   1,144ms OpenSSL
    # 4096-bit  7,269ms Perl  12,888ms OpenSSL

    $param{Standard} = $keygen->{Standard}
      if defined $keygen->{Standard} && !defined $param{Standard};
    my $standard = (defined $param{Standard} && $param{Standard} =~ /186-[34]/)
                 ? 'FIPS 186-4'
                 : 'FIPS 186-2';

    my($counter, $q, $p, $seed, $seedp1);

    if ($standard eq 'FIPS 186-2') {

      croak "FIPS 186-2 does not support Q sizes other than 160"
        if defined $param{QSize} && $param{QSize} != 160;
      # See FIPS 186-4 A.1.1.1, non-approved method.
      delete $param{Seed} if defined $param{Seed} && length($param{Seed}) != 20;

      my $n = int(($bits+159)/160)-1;
      my $b = $bits-1-($n*160);
      my $p_test = Math::BigInt->new(2)->bpow($bits-1);   # 2^(L-1)

      do {
        ## Generate q
        while (1) {
          print STDERR "." if $v;
          $seed = (defined $param{Seed}) ? delete $param{Seed}
                                         : randombytes(20);
          $seedp1 = _seed_plus_one($seed);
          my $md = sha1($seed) ^ sha1($seedp1);
          vec($md, 0, 8) |= 0x80;
          vec($md, 19, 8) |= 0x01;
          $q = bin2mp($md);
          last if ( $proveq && is_provable_prime($q))
               || (!$proveq && is_prob_prime($q)
                            && miller_rabin_random($q, 19, "0x$seedp1"));
        }
        print STDERR "*\n" if $v;

        ## Generate p.
        $counter = 0;
        my $q2 = Math::BigInt->new(2)->bmul($q);
        while ($counter < 4096) {
          print STDERR "." if $v;
          my $Wstr = '';
          for my $j (0 .. $n) {
            $seedp1 = _seed_plus_one($seedp1);
            $Wstr = sha1_hex($seedp1) . $Wstr;
          }
          my $W = Math::BigInt->from_hex($Wstr)->bmod($p_test);
          my $X = $W + $p_test;
          $p = $X - ( ($X % $q2) - 1);
          if ($p >= $p_test) {
            last if ( $provep && is_provable_prime($p))
                 || (!$provep && is_prob_prime($p)
                              && miller_rabin_random($p, 3, "0x$seedp1"));
          }
          $counter++;
        }
      } while ($counter >= 4096);

                # ▲▲▲▲▲ FIPS 186-2 ▲▲▲▲▲
    } else {
                # ▼▼▼▼▼ FIPS 186-4 ▼▼▼▼▼

      my $L = $bits;
      my $N = (defined $param{QSize}) ? $param{QSize}
                                      : ($bits >= 2048) ? 256 : 160;
      croak "Invalid Q size, must be between 1 and 512" if $N < 1 || $N > 512;
      croak "Invalid Q size, must be >= Size+8" if $L < $N+8;
      # See NIST SP 800-57 rev 3, table 3.  sha256 is ok for all sizes
      my $outlen = ($N <= 256) ? 256 : ($N <= 384) ? 384 : 512;
      my $sha = Digest::SHA->new($outlen);

      delete $param{Seed} if defined $param{Seed}
                          && 8*length($param{Seed}) < $N;

      my $n = int(($L+$outlen-1)/$outlen)-1;
      my $b = $L-1-($n*$outlen);
      my $p_test = Math::BigInt->new(2)->bpow($L-1);   # 2^(L-1)
      my $q_test = Math::BigInt->new(2)->bpow($N-1);   # 2^(N-1)
      my $seedlen = int( ($N+7)/8 );
      my $nptests = ($L <= 2048) ? 3 : 2;   # See FIPS 186-4 table C.1
      my $nqtests = ($N <= 160) ? 19 : 27;

      do {
        ## Generate q
        while (1) {
          print STDERR "." if $v;
          $seed = randombytes($seedlen);
          my $digest = $sha->reset->add($seed)->hexdigest;
          my $U = Math::BigInt->from_hex($digest)->bmod($q_test);
          $q = $q_test + $U + 1 - $U->is_odd();
          last if ( $proveq && is_provable_prime($q))
               || (!$proveq && is_prob_prime($q)
                            && miller_rabin_random($q, $nqtests, "0x$seed"));
        }
        print STDERR "*\n" if $v;
        $seedp1 = $seed;

        ## Generate p.
        $counter = 0;
        my $q2 = Math::BigInt->new(2)->bmul($q);
        while ($counter < 4*$L) {
          print STDERR "." if $v;
          my $Wstr = '';
          for my $j (0 .. $n) {
            $seedp1 = _seed_plus_one($seedp1);
            $Wstr = $sha->reset->add($seedp1)->hexdigest . $Wstr;
          }
          my $W = Math::BigInt->from_hex($Wstr)->bmod($p_test);
          my $X = $W + $p_test;
          $p = $X - ( ($X % $q2) - 1);
          if ($p >= $p_test) {
            last if ( $provep && is_provable_prime($p))
                 || (!$provep && is_prob_prime($p)
                              && miller_rabin_random($p,$nptests, "0x$seedp1"));
          }
          $counter++;
        }
      } while ($counter >= 4*$L);

    }

    print STDERR "*" if $v;
    my $e = ($p - 1) / $q;
    my $h = Math::BigInt->bone;
    my $g;
    do {
      $g = mod_exp(++$h, $e, $p);
    } while $g == 1;
    print STDERR "\n" if $v;

    my $key = Crypt::DSA::GMP::Key->new;
    $key->p($p);
    $key->q($q);
    $key->g($g);

    return wantarray ? ($key, $counter, "$h", $seed) : $key;
}

sub generate_keys {
    my ($keygen, $key) = @_;
    my($priv_key, $pub_key);
    my $q = $key->q;
    do {
        $priv_key = makerandom(Size => bitsize($q))->bmod($q);
    } while $priv_key == 0;
    $pub_key = mod_exp($key->g, $priv_key, $key->p);
    $key->priv_key($priv_key);
    $key->pub_key($pub_key);
}

sub _seed_plus_one {
    my($s) = @_;
    for (my $i = length($s)-1; $i >= 0; $i--) {
        vec($s, $i, 8)++;
        last unless vec($s, $i, 8) == 0;
    }
    return $s;
}

1;

=pod

=head1 NAME

Crypt::DSA::KeyChain - DSA key generation system

=head1 SYNOPSIS

    use Crypt::DSA::KeyChain;
    my $keychain = Crypt::DSA::KeyChain->new;

    my $key = $keychain->generate_params(
                    Size      => 512,
                    Seed      => $seed,
                    Verbosity => 1,
              );

    $keychain->generate_keys($key);

=head1 DESCRIPTION

I<Crypt::DSA::KeyChain> is a lower-level interface to key
generation than the interface in I<Crypt::DSA> (the I<keygen>
method). It allows you to separately generate the I<p>, I<q>,
and I<g> key parameters, given an optional starting seed, and
a mandatory bit size for I<p> (I<q> will be 160 or 256 bits,
and I<g> will be the same size as I<p>).

You can then call I<generate_keys> to generate the public and
private portions of the key.

=head1 USAGE

=head2 $keychain = Crypt::DSA::KeyChain->new

Constructs a new I<Crypt::DSA::KeyChain> object. At the moment
this isn't particularly useful in itself, other than being the
object you need in order to call the other methods.

Returns the new object.

=head2 $key = $keychain->generate_params(%arg)

Generates a set of DSA parameters: the I<p>, I<q>, and I<g>
values of the key. This involves finding primes, and as such
it can be a relatively long process.

When invoked in scalar context, returns a new
I<Crypt::DSA::Key> object.

In list context, returns the new I<Crypt::DSA::Key> object,
along with: the value of the internal counter when a suitable
prime I<p> was found; the value of I<h> when I<g> was derived;
and the value of the seed (a 20-byte or 32-byte string) when
I<q> was found. These values aren't particularly useful in normal
circumstances, but they could be useful.

I<%arg> can contain:

=over 4

=item * Standard

Indicates which standard is to be followed.  By default,
FIPS 186-2 is used, which maintains backward compatibility
with the Crypt::DSA Perl code and old OpenSSL versions.  If
C<FIPS 186-3> or C<FIPS 186-4> is given, then the FIPS 186-4
key generation will be used.

=item * Size

The size in bits of the I<p> value to generate. The I<q> and
I<g> values are always 160 bits each.

This argument is mandatory.

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
in just that prime being proven.

Using this flag will guarantee the values are prime, which is
valuable if security is extremely important.  Note that this
constructs random primes using the method A.1.1.1, then ensures
they are prime by using a primality proof, rather than using a
constructive method such as the Maurer or Shawe-Taylor
algorithms.  The time for proof will depend on the platform
and the Size parameter.  Proving I<q> should take 100ms or
less, but I<p> can take a very long time if over 1024 bits.

The default is 0, which means the standard FIPS 186-4 probable
prime tests are done.


=back

=head2 $keychain->generate_keys($key)

Generates the public and private portions of the key I<$key>,
a I<Crypt::DSA::Key> object.

=head1 AUTHOR & COPYRIGHT

See L<Crypt::DSA::GMP> for author, copyright, and license information.

=cut
