%%% Copyright   : (C) 2003-2010 Pattern Matched Technologies (Pty) Ltd. 
%%% File        : ecrypto_ecies.erl
%%% Author      : Andre du Preez <>
%%% Description : 
%%% Created     :  9 Jan 2018 by Andre du Preez <>

-module(ecrypto_ecies).

-export([
	 ecies_with_aescbc128_sha1/1,
	 ecies_with_aescbc128_sha224/1,
	 ecies_with_aescbc128_sha256/1,
	 ecies_with_aescbc256_sha256/1,
	 generate_key/1,
	 kdf2/4,
	 encrypt/3,
	 decrypt/3
	]).

%%==========================================================================================
-record(ecies_param,{ curve_name, kdf_mac, cipher, cipher_padding, key_size, cipher_block_size, mac }).
%%==========================================================================================

ecies_with_aescbc128_sha1(CurveName) ->
  #ecies_param{ curve_name        = CurveName,
		kdf_mac           = sha,
		cipher            = aes_cbc128,
		cipher_padding    = pkcs7,
		key_size          = 16,
		cipher_block_size = 16,
		mac               = sha
	       }.

ecies_with_aescbc128_sha224(CurveName) ->
  #ecies_param{ curve_name        = CurveName,
		kdf_mac           = sha,
		cipher            = aes_cbc128,
		cipher_padding    = pkcs7,
		key_size          = 16,
		cipher_block_size = 16,
		mac               = sha224
	       }.

ecies_with_aescbc128_sha256(CurveName) ->
  #ecies_param{ curve_name        = CurveName,
		kdf_mac           = sha,
		cipher            = aes_cbc128,
		cipher_padding    = pkcs7,
		key_size          = 16,
		cipher_block_size = 16,
		mac               = sha256
	       }.

ecies_with_aescbc256_sha256(CurveName) ->
  #ecies_param{ curve_name        = CurveName,
		kdf_mac           = sha,
		cipher            = aes_cbc256,
		cipher_padding    = pkcs7,
		key_size          = 32,
		cipher_block_size = 16,
		mac               = sha256
	       }.

%%==========================================================================================


%%==========================================================================================
%% IEEEE P 1683a KDF2
%%==========================================================================================

kdf2(SharedSecret,ExtraData,KeyOutputSize,HashAlgoritm) when is_binary(SharedSecret),
							     is_binary(ExtraData),
							     is_integer(KeyOutputSize),
							     is_atom(HashAlgoritm) ->
  HashSize = hash_size(HashAlgoritm),
  RepCount = (KeyOutputSize + HashSize - 1) div HashSize,
  MaxCounter = round(math:pow(2,32)),
  F = fun(Counter,Results) ->
	  Hash = crypto:hash(HashAlgoritm,<<SharedSecret/binary,(Counter rem MaxCounter):32,ExtraData/binary>>),
	  <<Results/binary,Hash/binary>>
      end,
  trunc_bin(lists:foldl(F,<<>>,lists:seq(1,RepCount)),KeyOutputSize).

%%==========================================================================================

generate_key(Param) when is_record(Param,ecies_param) ->
  crypto:generate_key(ecdh,Param#ecies_param.curve_name).

%%==========================================================================================

encrypt(OtherStaticPubKey,Data,Param) when is_binary(OtherStaticPubKey), is_binary(Data), is_record(Param,ecies_param) ->
  %% Generate a new ephemeral EC key pair
  {EphemeralPubKey,EphemeralPrivKey} = generate_key(Param),
  
  %% Calculate Shared Secret with ECDH
  SharedSecret = crypto:compute_key(ecdh,OtherStaticPubKey,EphemeralPrivKey,Param#ecies_param.curve_name),

  %% Using KDF2 to get MAC and ENC Keys
  KeySize = Param#ecies_param.key_size,
  <<EncKey:KeySize/binary,MacKey:KeySize/binary>> = kdf2(<<EphemeralPubKey/binary,SharedSecret/binary>>,<<>>,KeySize * 2,Param#ecies_param.kdf_mac),
  
  %% Encrypt using ENC Key and 000...IV
  IV = <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>,
  EncData = crypto:block_encrypt(Param#ecies_param.cipher,EncKey,IV,cipher_pad(Data,Param)),
  
  %% Calc Mac Tag using encrypted data
  MacTag = calc_mac_tag(EncData,MacKey,Param),
  
  <<EphemeralPubKey/binary,EncData/binary,MacTag/binary>>.

%%==========================================================================================

decrypt(StaticPrivKey,EncBlock,Param) when is_binary(StaticPrivKey), is_binary(EncBlock), is_record(Param,ecies_param) ->
  try
    PubKeySize = ec_pub_key_size(Param#ecies_param.curve_name),
    MacSize    = hash_size(Param#ecies_param.mac),
    DataSize   = size(EncBlock) - PubKeySize - hash_size(Param#ecies_param.mac),
    case EncBlock of
      <<OtherEphemeralPubKey:PubKeySize/binary,EncData:DataSize/binary,MacTag1:MacSize/binary>> ->
	
	%% Calculate Shared Secret with ECDH
	SharedSecret = crypto:compute_key(ecdh,OtherEphemeralPubKey,StaticPrivKey,Param#ecies_param.curve_name),

	%% Using KDF2 to get MAC and ENC Keys
	KeySize = Param#ecies_param.key_size,
	<<EncKey:KeySize/binary,MacKey:KeySize/binary>> = kdf2(<<OtherEphemeralPubKey/binary,SharedSecret/binary>>,<<>>,KeySize * 2,Param#ecies_param.kdf_mac),
	
	%% Verify Mac Tag using encrypted data
	validate_mac_tag(EncData,MacKey,MacTag1,Param),
	
	IV = <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>,
	Data = crypto:block_decrypt(Param#ecies_param.cipher,EncKey,IV,EncData),
	cipher_unpad(Data,Param);
      _ ->
	throw({invalid_ecies_decrypt_block,[]})
    end
  catch
    error:badarg ->
      throw({invalid_ecies_decrypt_block,[]})
  end.
      

%%==========================================================================================

cipher_pad(Data,Param) when Param#ecies_param.cipher_padding =:= pkcs7 ->
  ecrypto_utils:pkcs7_pad(Data,Param#ecies_param.cipher_block_size);
cipher_pad(_Data,Param) ->
  throw({unsupported_cipher_padding,[{padding,Param#ecies_param.cipher_padding}]}).

cipher_unpad(Data,Param) when Param#ecies_param.cipher_padding =:= pkcs7 ->
  ecrypto_utils:pkcs7_unpad(Data);
cipher_unpad(_Data,Param) ->
  throw({unsupported_cipher_padding,[{padding,Param#ecies_param.cipher_padding}]}).

%%-------------------------------------------------------------------------------------------
calc_mac_tag(EncData,MacKey,Param) ->
  MacData = <<EncData/binary,0:64>>,
  crypto:hmac(Param#ecies_param.mac,MacKey,MacData).  

validate_mac_tag(EncData,MacKey,MacTag1,Param) ->
  MacData = <<EncData/binary,0:64>>,
  case crypto:hmac(Param#ecies_param.mac,MacKey,MacData) of
    MacTag1  -> ok;
    _MacTag2 -> throw({invalid_ecies_mac,[]})
  end.
%%-------------------------------------------------------------------------------------------
trunc_bin(Data,Size) when is_binary(Data) andalso (size(Data) >= Size) ->
  <<TruncData:Size/binary,_/binary>> = Data,
  TruncData;
trunc_bin(Data,_Size) ->
  Data.
%%-------------------------------------------------------------------------------------------
hash_size(sha)    -> 20;
hash_size(sha224) -> 28;
hash_size(sha256) -> 32;
hash_size(sha384) -> 48;
hash_size(sha512) -> 64;
hash_size(Algorithm) -> throw({invalid_hash_algorithm,Algorithm}).
%%-------------------------------------------------------------------------------------------
ec_pub_key_size(secp160r1) -> 41;
ec_pub_key_size(secp160r2) -> 41;
ec_pub_key_size(secp160k1) -> 41;
ec_pub_key_size(secp192k1) -> 49;
ec_pub_key_size(secp192r1) -> 49;
ec_pub_key_size(secp224k1) -> 57;
ec_pub_key_size(secp224r1) -> 57;
ec_pub_key_size(secp256k1) -> 65;
ec_pub_key_size(secp256r1) -> 65;
ec_pub_key_size(secp384r1) -> 97;
ec_pub_key_size(secp521r1) -> 133;

ec_pub_key_size(sect113r1) -> 31;
ec_pub_key_size(sect113r2) -> 31;
ec_pub_key_size(sect131r1) -> 35;
ec_pub_key_size(sect131r2) -> 35;
ec_pub_key_size(sect163k1) -> 43;
ec_pub_key_size(sect163r1) -> 43;
ec_pub_key_size(sect163r2) -> 43;
ec_pub_key_size(sect233k1) -> 61;
ec_pub_key_size(sect233r1) -> 61;
ec_pub_key_size(sect239k1) -> 61;
ec_pub_key_size(sect283k1) -> 73;
ec_pub_key_size(sect283r1) -> 73;
ec_pub_key_size(sect409r1) -> 105;
ec_pub_key_size(sect409k1) -> 105;
ec_pub_key_size(sect571k1) -> 145;
ec_pub_key_size(sect571r1) -> 145;
ec_pub_key_size(CurveName) -> throw({ec_curve_not_supported,[{curvename,CurveName}]}).
%%-------------------------------------------------------------------------------------------

