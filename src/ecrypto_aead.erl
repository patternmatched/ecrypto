%%% Copyright   : (C) 2003-2019 Pattern Matched Technologies (Pty) Ltd.
%%% Description : 
%%% Created     : 13 Sep 2019 by Andre du Preez <>
%%==========================================================================================
-module(ecrypto_aead).
%%==========================================================================================

-export([
         aes_cbc_hmac/1, aes_cbc_hmac/2,
         aes128_cbc_sha256/0,
         aes192_cbc_sha384/0,
         aes256_cbc_sha512/0,
         
         encrypt/4, encrypt/5,
         decrypt/4, decrypt/5
        ]).

%%==========================================================================================
-record(aead_params,{ kdf_mac, cipher, cipher_padding, key_size, cipher_block_size, mac, mac_length }).
%%==========================================================================================

aes_cbc_hmac(BitSize,MacAlgorithm) ->
  #aead_params{ kdf_mac           = sha,
                cipher            = aes_cbc,
                cipher_padding    = pkcs7,
                key_size          = BitSize div 8,
                cipher_block_size = 16,
                mac               = MacAlgorithm,
                mac_length        = ecrypto_utils:hash_size(MacAlgorithm) div 2
               }.

aes_cbc_hmac(128) -> aes128_cbc_sha256();
aes_cbc_hmac(192) -> aes192_cbc_sha384();
aes_cbc_hmac(256) -> aes256_cbc_sha512().

aes128_cbc_sha256() -> aes_cbc_hmac(128,sha256).
aes192_cbc_sha384() -> aes_cbc_hmac(192,sha384).
aes256_cbc_sha512() -> aes_cbc_hmac(256,sha512).

%%==========================================================================================

encrypt(Key,Data,AAD,Params) when is_binary(Data) ->
  {EncKey,MacKey} = kdf(Key,AAD,Params),
  Vector = crypto:strong_rand_bytes(Params#aead_params.cipher_block_size),
  EncData = block_encrypt(EncKey,Vector,Data,Params),
  MAC = calc_mac_tag(AAD,Vector,EncData,MacKey,Params),
  binary:list_to_bin([Vector,EncData,MAC]).

encrypt(Key,IV,Data,AAD,Params) when is_binary(Data) ->
  {EncKey,MacKey} = kdf(Key,AAD,Params),
  Vector = <<IV:(Params#aead_params.cipher_block_size)/binary>>,
  EncData = block_encrypt(EncKey,Vector,Data,Params),
  MAC = calc_mac_tag(AAD,Vector,EncData,MacKey,Params),
  binary:list_to_bin([EncData,MAC]).

decrypt(Key,Data,AAD,Params) ->
  {EncKey,MacKey} = kdf(Key,AAD,Params),
  {Vector,EncData,MacTag} = extract(Data,Params,true),
  validate_mac_tag(AAD,Vector,EncData,MacKey,MacTag,Params),
  block_decrypt(EncKey,Vector,EncData,Params).

decrypt(Key,IV,Data,AAD,Params) ->
  {EncKey,MacKey} = kdf(Key,AAD,Params),
  {EncData,MacTag} = extract(Data,Params,false),
  Vector = <<IV:(Params#aead_params.cipher_block_size)/binary>>,
  validate_mac_tag(AAD,Vector,EncData,MacKey,MacTag,Params),
  block_decrypt(EncKey,Vector,EncData,Params).

%%=========================================================================================================

kdf(Key,AAD,Params) ->
  KeySize = Params#aead_params.key_size,
  KdfMac  = Params#aead_params.kdf_mac,
  <<EncKey:KeySize/binary,MacKey:KeySize/binary>> = ecrypto_key:kdf2(Key,AAD,KeySize * 2,KdfMac),
  {EncKey,MacKey}.

pad(Data,Param) when Param#aead_params.cipher_padding =:= pkcs7 ->
  ecrypto_utils:pkcs7_pad(Data,Param#aead_params.cipher_block_size);
pad(_Data,Param) ->
  throw({unsupported_cipher_padding,[{padding,Param#aead_params.cipher_padding}]}).

unpad(Data,Param) when Param#aead_params.cipher_padding =:= pkcs7 ->
  ecrypto_utils:pkcs7_unpad(Data);
unpad(_Data,Param) ->
  throw({unsupported_cipher_padding,[{padding,Param#aead_params.cipher_padding}]}).

block_encrypt(EncKey,Vector,Data,Params) ->
  crypto:block_encrypt(Params#aead_params.cipher,EncKey,Vector,pad(Data,Params)).

block_decrypt(EncKey,Vector,Data,Params) ->
  unpad(crypto:block_decrypt(Params#aead_params.cipher,EncKey,Vector,Data),Params).

extract(Data,Params,IVIncluded) ->
  BlockSize = Params#aead_params.cipher_block_size,
  HashSize  = Params#aead_params.mac_length,
  DataSize  = case IVIncluded of
                false -> size(Data) - HashSize;
                true  -> size(Data) - BlockSize - HashSize
              end,
  case Data of
    <<Vector:BlockSize/binary,EncData:DataSize/binary,HashedValue:HashSize/binary>> when (IVIncluded =:= true) ->
      {Vector,EncData,HashedValue};
    <<EncData:DataSize/binary,HashedValue:HashSize/binary>> when (IVIncluded =:= false) ->
      {EncData,HashedValue};
    _InvalidData ->
      throw({crypto_error,[]})
  end.

calc_mac_tag(AAD,Vector,EncData,MacKey,Params) ->
  AADLen = <<(size(AAD)*8):64/integer>>,
  MacData = <<AAD/binary,Vector/binary,EncData/binary,AADLen/binary>>,
  crypto:hmac(Params#aead_params.mac,MacKey,MacData,Params#aead_params.mac_length).

validate_mac_tag(AAD,Vector,EncData,MacKey,MacTag,Params) ->
  AADLen = <<(size(AAD)*8):64/integer>>,
  MacData = <<AAD/binary,Vector/binary,EncData/binary,AADLen/binary>>,
  case MacTag =:= crypto:hmac(Params#aead_params.mac,MacKey,MacData,Params#aead_params.mac_length) of
    false -> throw({crypto_error,[]});
    true  -> ok
  end.

