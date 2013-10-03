package Crypt::DSA::GMP::Key;
use strict;
use warnings;

BEGIN {
  $Crypt::DSA::GMP::Key::AUTHORITY = 'cpan:DANAJ';
  $Crypt::DSA::GMP::Key::VERSION = '0.01';
}

use Carp qw( croak );
use Math::BigInt lib => "GMP";
use Crypt::DSA::GMP::Util qw( bitsize );


sub new {
    my ($class, %param) = @_;
    my $key = bless { }, $class;

    if ($param{Filename} || $param{Content}) {
        if ($param{Filename} && $param{Content}) {
            croak "Filename and Content are mutually exclusive.";
        }
        return $key->read(%param);
    }
    $key;
}

sub size { bitsize($_[0]->p) }

BEGIN {
    no strict 'refs';  ## no critic (ProhibitNoStrict)
    for my $meth (qw( p q g pub_key priv_key r kinv )) {
        # Values are stored as Math::BigInt objects
        *$meth = sub {
            my($key, $value) = @_;
            if (defined $value) {
              my $str;
              if (ref($value) eq 'Math::BigInt')  { $key->{$meth} = $value; }
              elsif (ref($value) eq 'Math::Pari') { $str = Math::Pari::pari2pv($value); }
              elsif (ref $value)                  { $str = "$value"; }
              elsif ($value =~ /^0x/)             { $key->{$meth} = Math::BigInt->new($value); }
              else                                { $str = $value; }
              $key->{$meth} = Math::BigInt->new("$str")
                  if defined $str && $str =~ /^\d+$/;
            } elsif (@_ > 1 && !defined $value) {
              delete $key->{$meth};
            }
            $key->{$meth};
        };
    }
}

sub read {
    my ($key, %param) = @_;
    my $type = $param{Type} or croak "read: Need a key file 'Type'";
    my $class = join '::', __PACKAGE__, $type;
    eval "use $class;";
    croak "Invalid key file type '$type': $@" if $@;
    bless $key, $class;
    if (my $fname = delete $param{Filename}) {
        open(my $fh, "<", $fname) or return;
        my $blob = do { local $/; <$fh> };
        close $fh or return;
        $param{Content} = $blob;
    }
    $key->deserialize(%param);
}

sub write {
    my ($key, %param) = @_;
    my $type;
    unless ($type = $param{Type}) {
        my $pkg = __PACKAGE__;
        ($type) = ref($key) =~ /^${pkg}::(\w+)$/;
    }
    croak "write: Need a key file 'Type'" unless $type;
    my $class = join '::', __PACKAGE__, $type;
    eval "use $class;";
    croak "Invalid key file type '$type': $@" if $@;
    bless $key, $class;
    my $blob = $key->serialize(%param);
    if (my $fname = delete $param{Filename}) {
        open(my $fh, ">", $fname) or croak "Can't open $fname: $!";
        print $fh $blob;
        close $fh or croak "Can't close $fname: $!";
    }
    $blob;
}

1;
__END__

=head1 NAME

Crypt::DSA::Key - DSA key

=head1 SYNOPSIS

    use Crypt::DSA::Key;
    my $key = Crypt::DSA::Key->new;

    $key->p($p);

=head1 DESCRIPTION

I<Crypt::DSA::Key> contains a DSA key, both the public and
private portions. Subclasses of I<Crypt::DSA::Key> implement
I<read> and I<write> methods, such that you can store DSA
keys on disk, and read them back into your application.

=head1 USAGE

Any of the key attributes can be accessed through combination
get/set methods. The key attributes are: I<p>, I<q>, I<g>,
I<priv_key>, and I<pub_key>. For example:

    $key->p($p);
    my $p2 = $key->p;

=head2 $key = Crypt::DSA::Key->new(%arg)

Creates a new (empty) key object. All of the attributes are
initialized to 0.

Alternately, if you provide the I<Filename> parameter (see
below), the key will be read in from disk. If you provide
the I<Type> parameter (mandatory if I<Filename> is provided),
be aware that your key will actually be blessed into a subclass
of I<Crypt::DSA::Key>. Specifically, it will be the class
implementing the specific read functionality for that type,
e.g. I<Crypt::DSA::Key::PEM>.

Returns the key on success, C<undef> otherwise. (See I<Password>
for one reason why I<new> might return C<undef>).

I<%arg> can contain:

=over 4

=item * Type

The type of file where the key is stored. Currently the only
option is I<PEM>, which indicates a PEM file (optionally
encrypted, ASN.1-encoded object). Support for reading/writing
PEM files comes from I<Convert::PEM>; if you don't have this
module installed, the I<new> method will die.

This argument is mandatory, I<if> you're either reading the file from
disk (i.e. you provide a I<Filename> argument) or you've specified the
I<Content> argument.

=item * Filename

The location of the file from which you'd like to read the key.
Requires a I<Type> argument so the decoder knows what type of file it
is.  You can't specify I<Content> and I<Filename> at the same time.

=item * Content

The serialized version of the key.  Requires a I<Type> argument so the
decoder knows how to decode it.  You can't specify I<Content> and
I<Filename> at the same time.

=item * Password

If your key file is encrypted, you'll need to supply a
passphrase to decrypt it. You can do that here.

If your passphrase is incorrect, I<new> will return C<undef>.

=back

=head2 $key->write(%arg)

Writes a key (optionally) to disk, using a format that you
define with the I<Type> parameter.

If your I<$key> object has a defined I<priv_key> (private key portion),
the key will be written as a DSA private key object; otherwise, it will
be written out as a public key. Note that not all serialization mechanisms
can produce public keys in this version--currently, only PEM public keys
are supported.

I<%arg> can include:

=over 4

=item * Type

The type of file format that you wish to write. I<PEM> is one
example (in fact, currently, it's the only example).

This argument is mandatory, I<unless> your I<$key> object is
already blessed into a subclass (e.g. I<Crypt::DSA::Key::PEM>),
and you wish to write the file using the same subclass.

=item * Filename

The location of the file on disk where you want the key file
to be written.

=item * Password

If you want the key file to be encrypted, provide this
argument, and the ASN.1-encoded string will be encrypted using
the passphrase as a key.

=back

=head2 $key->size

Returns the size of the key, in bits. This is actually the
number of bits in the large prime I<p>.

=head1 AUTHOR & COPYRIGHTS

See L<Crypt::DSA::GMP> for author, copyright, and license information.

=cut
