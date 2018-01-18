%%%-------------------------------------------------------------------
%%% Copyright   : (C) 2003-2010 Pattern Matched Technologies (Pty) Ltd. 
%%% File        : ecrypto_ecies_SUITE.erl
%%% Author      : Andre du Preez <>
%%% Description : 
%%%
%%% Created     : 18 Jan 2018 by Andre du Preez <>
%%%-------------------------------------------------------------------
-module(ecrypto_ecies_SUITE).

-compile(export_all).

-include_lib("test_server/include/test_server.hrl").

init_per_suite(Config) ->
  Config.

end_per_suite(_Config) ->
  ok.

init_per_testcase(_TestCase, Config) ->
  Config.

end_per_testcase(_TestCase, _Config) ->
  ok.

all() ->
  all(suite).

all(doc) -> 
  [""];

all(suite) -> 
  [
   test_ecies_param,
   test_ecies_validations,
   test_ecies_with_aescbc128_sha256_secp256r1,
   test_ecies_with_aescbc128_sha256_secp521r1,
   test_ecies_with_aescbc128_sha256_sect283r1,
   test_ecies_with_aescbc128_sha256_sect571r1,
   
   test_ecies_with_aescbc256_sha256_secp256r1,
   test_ecies_with_aescbc128_sha224_secp256r1
  ].

-define(ASSERT_THROW(Code,ExpectedThrow), try Code catch throw:{ExpectedThrow,_} -> ok; throw:ExpectedThrow -> ok end).

%%--------------------------------------------------------------------

test_ecies_param(suite) ->
  [];
test_ecies_param(Config) when is_list(Config) ->  
  {ecies_param,secp256r1,sha,aes_cbc128,pkcs7,16,16,sha224} = ecrypto_ecies:ecies_with_aescbc128_sha224(secp256r1),
  {ecies_param,secp256r1,sha,aes_cbc128,pkcs7,16,16,sha256} = ecrypto_ecies:ecies_with_aescbc128_sha256(secp256r1),
  {ecies_param,secp384r1,sha,aes_cbc256,pkcs7,32,16,sha256} = ecrypto_ecies:ecies_with_aescbc256_sha256(secp384r1),
  ok.

%%--------------------------------------------------------------------

test_ecies_validations(suite) ->
  [];
test_ecies_validations(Config) when is_list(Config) ->  
  ECIESParam = ecrypto_ecies:ecies_with_aescbc128_sha256(secp256r1),
  {StaticPubKey1,StaticPrivKey1} = ecrypto_ecies:generate_key(ECIESParam),
  
  %% Ciper Block Padding
  ?line 113 = size(ecrypto_ecies:encrypt(StaticPubKey1,<<>>,ECIESParam)),  
  ?line 113 = size(ecrypto_ecies:encrypt(StaticPubKey1,<<"123456789012345">>,ECIESParam)),
  ?line 129 = size(ecrypto_ecies:encrypt(StaticPubKey1,<<"1234567890123456">>,ECIESParam)),

  %% TEST DECRYPT: empty data
  ?ASSERT_THROW(ecrypto_ecies:decrypt(StaticPrivKey1,<<>>,ECIESParam), invalid_ecies_decrypt_block),
  %% TEST DECRYPT: empty data
  ?ASSERT_THROW(ecrypto_ecies:decrypt(StaticPrivKey1,list_to_binary(lists:duplicate(113,$0)),ECIESParam), invalid_ecies_decrypt_block),
  ok.

%%--------------------------------------------------------------------

test_ecies_with_aescbc128_sha256_secp256r1(suite) -> 
  [];
test_ecies_with_aescbc128_sha256_secp256r1(Config) when is_list(Config) ->
  ECIESParam = ecrypto_ecies:ecies_with_aescbc128_sha256(secp256r1),
  {StaticPubKey1,StaticPrivKey1} = ecrypto_ecies:generate_key(ECIESParam),
  ClearData = <<"1234567890123456">>,
  EncBlock = ecrypto_ecies:encrypt(StaticPubKey1,ClearData,ECIESParam),
  ?line 129 = size(EncBlock),
  ?line ClearData = ecrypto_ecies:decrypt(StaticPrivKey1,EncBlock,ECIESParam),
  ok.

%%--------------------------------------------------------------------

test_ecies_with_aescbc128_sha256_secp521r1(suite) -> 
  [];
test_ecies_with_aescbc128_sha256_secp521r1(Config) when is_list(Config) ->
  ECIESParam = ecrypto_ecies:ecies_with_aescbc128_sha256(secp521r1),
  {StaticPubKey1,StaticPrivKey1} = ecrypto_ecies:generate_key(ECIESParam),
  ClearData = <<"1234567890123456">>,
  EncBlock = ecrypto_ecies:encrypt(StaticPubKey1,ClearData,ECIESParam),
  ?line 197 = size(EncBlock),
  ?line ClearData = ecrypto_ecies:decrypt(StaticPrivKey1,EncBlock,ECIESParam),
  ok.

%%--------------------------------------------------------------------

test_ecies_with_aescbc128_sha256_sect283r1(suite) -> 
  [];
test_ecies_with_aescbc128_sha256_sect283r1(Config) when is_list(Config) ->
  ECIESParam = ecrypto_ecies:ecies_with_aescbc128_sha256(sect283r1),
  {StaticPubKey1,StaticPrivKey1} = ecrypto_ecies:generate_key(ECIESParam),
  ClearData = <<"1234567890123456">>,
  EncBlock = ecrypto_ecies:encrypt(StaticPubKey1,ClearData,ECIESParam),
  ?line 137 = size(EncBlock),
  ?line ClearData = ecrypto_ecies:decrypt(StaticPrivKey1,EncBlock,ECIESParam),
  ok.

test_ecies_with_aescbc128_sha256_sect571r1(suite) -> 
  [];
test_ecies_with_aescbc128_sha256_sect571r1(Config) when is_list(Config) ->
  ECIESParam = ecrypto_ecies:ecies_with_aescbc128_sha256(sect571r1),
  {StaticPubKey1,StaticPrivKey1} = ecrypto_ecies:generate_key(ECIESParam),
  ClearData = <<"1234567890123456">>,
  EncBlock = ecrypto_ecies:encrypt(StaticPubKey1,ClearData,ECIESParam),
  ?line 209 = size(EncBlock),
  ?line ClearData = ecrypto_ecies:decrypt(StaticPrivKey1,EncBlock,ECIESParam),
  ok.

%%--------------------------------------------------------------------

test_ecies_with_aescbc256_sha256_secp256r1(suite) -> 
  [];
test_ecies_with_aescbc256_sha256_secp256r1(Config) when is_list(Config) ->
  ECIESParam = ecrypto_ecies:ecies_with_aescbc256_sha256(secp256r1),
  {StaticPubKey1,StaticPrivKey1} = ecrypto_ecies:generate_key(ECIESParam),
  ClearData = <<"1234567890123456">>,
  EncBlock = ecrypto_ecies:encrypt(StaticPubKey1,ClearData,ECIESParam),
  ?line 129 = size(EncBlock),
  ?line ClearData = ecrypto_ecies:decrypt(StaticPrivKey1,EncBlock,ECIESParam),
  ok.

%%--------------------------------------------------------------------

test_ecies_with_aescbc128_sha224_secp256r1(suite) -> 
  [];
test_ecies_with_aescbc128_sha224_secp256r1(Config) when is_list(Config) ->
  ECIESParam = ecrypto_ecies:ecies_with_aescbc128_sha224(secp256r1),
  {StaticPubKey1,StaticPrivKey1} = ecrypto_ecies:generate_key(ECIESParam),
  ClearData = <<"1234567890123456">>,
  EncBlock = ecrypto_ecies:encrypt(StaticPubKey1,ClearData,ECIESParam),
  ?line 125 = size(EncBlock),
  ?line ClearData = ecrypto_ecies:decrypt(StaticPrivKey1,EncBlock,ECIESParam),
  ok.
