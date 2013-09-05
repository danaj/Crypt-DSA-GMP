package Crypt::DSA::KeyChain;

use strict;
use Math::BigInt lib => "GMP";
use Math::Prime::Util::GMP qw/is_prob_prime is_provable_prime miller_rabin_random/;
use Digest::SHA qw( sha1 sha1_hex sha256 sha256_hex);
use Carp qw( croak );

use vars qw{$VERSION};
BEGIN {
    $VERSION = '1.17';
}

use Crypt::DSA::Key;
use Crypt::DSA::Util qw( bin2mp bitsize mod_exp makerandom randombytes );

sub new {
    my $class = shift;
    bless { @_ }, $class;
}

sub generate_params {
    my $keygen = shift;
    my %param  = @_;
    my $bits   = int($param{Size});
    croak "Number of bits (Size => $bits) is too small" unless $bits >= 256;
    #delete $param{Seed} if $param{Seed} && length $param{Seed} != 20;
    my $v = $param{Verbosity};
    my $proveq = $param{Prove} && $param{Prove} !~ /^p$/i;
    my $provep = $param{Prove} && $param{Prove} !~ /^q$/i;

    # OpenSSL was removed to avoid portability concerns.  With the redone
    # code below plus Math::Prime::Util::GMP for primality testing, we're
    # actually faster in many cases, plus we know we're following FIPS.

    # OpenSSL also has lots of undocumented behavior that doesn't match the
    # Crypt::DSA Pure Perl implementation.  For instance, Size gets rounded
    # up to 512 silently.  In contrast, Crypt::DSA will generate composites
    # when the size is small enough. (there should be an RT).
    # When Size >= 2048, q is bumped to 256 bits.

    # TODO:
    #   - allow Q size to be selected
    #   - add provable option for q, maybe p

    my($counter, $q, $p, $seed, $seedp1);

    if (defined $param{Seed} && length($param{Seed}) == 20) {

        # Old school.  FIPS 186-4 A.1.1.1, non-approved method.
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
                next unless is_prob_prime($q);
                if ($proveq) { last if is_provable_prime($q); }
                else         { last if miller_rabin_random($q, 19, "0x$seedp1"); }
            }
            print STDERR "*\n" if $v;

            ## Generate p.
            $counter = 0;
            my $q2 = Math::BigInt->new(2)->bmul($q);
            while ($counter < 4096) {
                print STDERR "." if $v;
                # This does the construction of FIPS 186-4 A.1.1.2 steps 11.1-2.
                my $Wstr = '';
                for my $j (0 .. $n) {
                    $seedp1 = _seed_plus_one($seedp1);
                    $Wstr = sha1_hex($seedp1) . $Wstr;
                }
                my $W = Math::BigInt->from_hex($Wstr)->bmod($p_test);
                my $X = $W + $p_test;
                $p = $X - ( ($X % $q2) - 1);
                last if $p >= $p_test
                     && is_prob_prime($p)
                     && miller_rabin_random($p, 3, "0x$seedp1");
                $counter++;
            }
        } while ($counter >= 4096);

    } else {

        # FIPS 186-4 A.1.1.2 approved method
        my $outlen = 256;   # sha256
        my $L = $bits;
        my $N = ($bits >= 2048) ? 256 : 160;  # Just like OpenSSL
        my $n = int(($L+$outlen-1)/$outlen)-1;
        my $b = $L-1-($n*$outlen);
        my $p_test = Math::BigInt->new(2)->bpow($L-1);   # 2^(L-1)
        my $q_test = Math::BigInt->new(2)->bpow($N-1);   # 2^(N-1)
        my $seedlen = int( ($N+7)/8 );
        # See FIPS 186-4 table C.1
        my $nptests = ($L <= 2048) ? 3 : 2;
        my $nqtests = ($N <= 160) ? 19 : 27;

        do {
            ## Generate q
            while (1) {
                print STDERR "." if $v;
                $seed = randombytes($seedlen);
                my $U = bin2mp(sha256($seed))->bmod($q_test);
                $q = $q_test + $U + 1 - $U->is_odd();
                #last if is_prob_prime($q)
                #     && miller_rabin_random($q, $nqtests, "0x$seed");
                #last if is_provable_prime($q)
                if ($proveq) { last if is_provable_prime($q); }
                else         { last if miller_rabin_random($q, 19, "0x$seed"); }
            }
            print STDERR "*\n" if $v;
            $seedp1 = $seed;

            ## Generate p.
            $counter = 0;
            my $q2 = Math::BigInt->new(2)->bmul($q);
            while ($counter < 4*$L) {
                print STDERR "." if $v;
                # This does the construction of FIPS 186-4 A.1.1.2 steps 11.1-2.
                my $Wstr = '';
                for my $j (0 .. $n) {
                    $seedp1 = _seed_plus_one($seedp1);
                    $Wstr = sha256_hex($seedp1) . $Wstr;
                }
                my $W = Math::BigInt->from_hex($Wstr)->bmod($p_test);
                my $X = $W + $p_test;
                $p = $X - ( ($X % $q2) - 1);
                if ($p >= $p_test && is_prob_prime($p)) {
                  if ($provep) { last if is_provable_prime($p); }
                  else         { last if miller_rabin_random($p, $nptests, "0x$seedp1"); }
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

    my $key = Crypt::DSA::Key->new;
    $key->p($p);
    $key->q($q);
    $key->g($g);

    return wantarray ? ($key, $counter, "$h", $seed) : $key;
}

sub generate_keys {
    my $keygen = shift;
    my $key = shift;
    my($priv_key, $pub_key);
    SCOPE: {
        my $i = bitsize($key->q);
        $priv_key = makerandom(Size => $i);
        $priv_key -= $key->q if $priv_key >= $key->q;
        redo if $priv_key == 0;
    }
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
    $s;
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
a mandatory bit size for I<p> (I<q> and I<g> are 160 bits each).

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
and the value of the seed (a 20-byte string) when I<q> was
found. These values aren't particularly useful in normal
circumstances, but they could be useful.

I<%arg> can contain:

=over 4

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

=back

=head2 $keychain->generate_keys($key)

Generates the public and private portions of the key I<$key>,
a I<Crypt::DSA::Key> object.

=head1 AUTHOR & COPYRIGHT

Please see the L<Crypt::DSA> manpage for author, copyright,
and license information.

=cut
