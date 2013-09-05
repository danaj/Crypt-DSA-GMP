use inc::Module::Install 1.01;

all_from      'lib/Crypt/DSA.pm';
requires      'IPC::Open3'   => 0;
requires      'File::Spec'   => 0;
requires      'Digest::SHA'  => 0;
requires      'MIME::Base64' => 0;
requires      'File::Which'  => '0.05';
requires      'Math::BigInt' => '1.78';
requires      'Data::Random' => '0.05' if win32;
requires      'Data::Buffer' => '0.01';
requires      'Math::BigInt::GMP' => '0.15';  # M-R random
#requires      'Bytes::Random::Secure'  => '0.23', # object->irand
requires      'Crypt::Random::Seed' => 0;
#requires      'Math::Prime::Util' => '0.17'; # pluggable irand
requires      'Math::Prime::Util::GMP' => 0;
test_requires 'Test::More'   => '0.42';

WriteAll;
