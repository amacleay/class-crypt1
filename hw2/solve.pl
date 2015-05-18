use strict;
use warnings;

use constant BLOCK_SIZE => 16;

use bignum;
use Crypt::OpenSSL::AES;

$| = 1;  #autoflush

my $k1 = '140b41b22a29beb4061bda66b6747e14';
my $cp1 = '4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81';

print join'', decrypt_cbc($k1, $cp1);

my $k2 = '140b41b22a29beb4061bda66b6747e14';
my $cp2 = '5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253';

print decrypt_cbc($k2, $cp2);

exit;

sub decrypt_cbc {
  my ($key, $cp) = @_;
  my $cipher = Crypt::OpenSSL::AES->new(
    convert_hex_string_to_chars($key)
  );

  # get the IV by pulling of the front of cp
  my $iv = strip_block_from_string(\$cp);
  
  # m[0] = D(k, c[0]) xor IV
  my (@message_blocks, $i);
  my $last_xor = $iv;
  do {
    my $cipher_block = strip_block_from_string(\$cp);
    my $decoded_bytes = $cipher->decrypt($cipher_block);

    $message_blocks[$i++] = $decoded_bytes ^ $last_xor;

    $last_xor = $cipher_block;
  } while $cp;

  # TODO: handle padding at the end!

  return @message_blocks;
}

sub ascii_encode {
  my $message_int = shift;

  my @chars;
  do {
    my $lsb = $message_int & hex('ff');
    unshift @chars, chr($lsb);
    $message_int = $message_int >> 8;
  } while $message_int > 0;
  return join '', @chars;
}

sub strip_block_from_string {
  my $string_ref = shift;

  ref $string_ref eq 'SCALAR'
    or die "Wanted string ref, got $string_ref";

  my $first_block = substr($$string_ref, 0, 2*BLOCK_SIZE);
  $$string_ref = substr($$string_ref, 2*BLOCK_SIZE);

  my $first_block_as_chars = convert_hex_string_to_chars($first_block);

  return $first_block_as_chars;
}

sub convert_hex_string_to_chars {
  my $string = shift;

  my @bytes;
  while ($string) {
    my $two_chars = substr($string, 0, 2);
    $string = substr($string, 2);
    push @bytes, chr(hex $two_chars);
  }
  return join '', @bytes;
}

