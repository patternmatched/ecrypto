%%==============================================================================
%%% Copyright   : (C) 2003-2019 Pattern Matched Technologies (Pty) Ltd.
%%% Description : 
%%% Created     : 13 Sep 2019 by Andre du Preez <>
%%==============================================================================
-module(ecrypto_aead_SUITE).

-compile(export_all).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

suite() ->
  [{timetrap, {minutes, 10}}].

init_per_suite(Config) ->
  Config.

end_per_suite(_Config) ->
  ok.

init_per_testcase(TestCase, Config) ->
  ?MODULE:TestCase({init, Config}).

end_per_testcase(TestCase, Config) ->
  ?MODULE:TestCase({terminate, Config}).

all() ->
  all(suite).

all(doc) ->
  [""];
all(suite) ->
  [
   test_encrypt_decrypt_aes128_cbc_sha256,
   test_encrypt_decrypt_aes128_cbc_sha256_external_iv,
   test_encrypt_decrypt_aes128_cbc_sha256_external_iv_and_aad,
   test_encrypt_decrypt_aes192_cbc_sha384,
   test_encrypt_decrypt_aes256_cbc_sha512
  ].

-define(ASSERT_THROW(Code,ExpectedThrow), try Code catch throw:{ExpectedThrow,_} -> ok; throw:ExpectedThrow -> ok end).

%%--------------------------------------------------------------------

test_encrypt_decrypt_aes128_cbc_sha256(suite) ->
  [];
test_encrypt_decrypt_aes128_cbc_sha256({init, Config}) ->
  Params = ecrypto_aead:aes128_cbc_sha256(),
  Key = <<1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6>>,
  [{key,Key},{params,Params}|Config];
test_encrypt_decrypt_aes128_cbc_sha256({terminate, _Config}) ->
  ok;
test_encrypt_decrypt_aes128_cbc_sha256(Config) when is_list(Config) ->
  Key = proplists:get_value(key,Config),

  Data = <<"123456789012345">>,
  EncData = ecrypto_aead:encrypt(Key,Data,<<>>,proplists:get_value(params,Config)),
  ?assertEqual(48,size(EncData)),
  Data = ecrypto_aead:decrypt(Key,EncData,<<>>,proplists:get_value(params,Config)),

  Data2 = <<"1234567890123456">>,
  EncData2 = ecrypto_aead:encrypt(Key,Data2,<<>>,proplists:get_value(params,Config)),
  ?assertEqual(64,size(EncData2)),
  Data2 = ecrypto_aead:decrypt(Key,EncData2,<<>>,proplists:get_value(params,Config)),
  ok.

test_encrypt_decrypt_aes128_cbc_sha256_external_iv(suite) ->
  [];
test_encrypt_decrypt_aes128_cbc_sha256_external_iv({init, Config}) ->
  Params = ecrypto_aead:aes128_cbc_sha256(),
  Key = <<1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6>>,
  [{key,Key},{params,Params}|Config];
test_encrypt_decrypt_aes128_cbc_sha256_external_iv({terminate, _Config}) ->
  ok;
test_encrypt_decrypt_aes128_cbc_sha256_external_iv(Config) when is_list(Config) ->
  Key = proplists:get_value(key,Config),
  Data = <<"123456789012345">>,
  IV = <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>,
  EncData = ecrypto_aead:encrypt(Key,IV,Data,<<>>,proplists:get_value(params,Config)),
  ?assertEqual(32,size(EncData)),
  Data = ecrypto_aead:decrypt(Key,IV,EncData,<<>>,proplists:get_value(params,Config)),
  ok.

test_encrypt_decrypt_aes128_cbc_sha256_external_iv_and_aad(suite) ->
  [];
test_encrypt_decrypt_aes128_cbc_sha256_external_iv_and_aad({init, Config}) ->
  Params = ecrypto_aead:aes128_cbc_sha256(),
  Key = <<1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6>>,
  [{key,Key},{params,Params}|Config];
test_encrypt_decrypt_aes128_cbc_sha256_external_iv_and_aad({terminate, _Config}) ->
  ok;
test_encrypt_decrypt_aes128_cbc_sha256_external_iv_and_aad(Config) when is_list(Config) ->
  Key = proplists:get_value(key,Config),
  Data = <<"123456789012345">>,
  IV = <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>,
  AAD = <<"AAAAA">>,
  EncData = ecrypto_aead:encrypt(Key,IV,Data,AAD,proplists:get_value(params,Config)),
  ?assertEqual(32,size(EncData)),
  %% Test Invalid AAD
  ?ASSERT_THROW( ecrypto_aead:decrypt(Key,IV,EncData,<<>>,proplists:get_value(params,Config)), crypto_error ),
  %% Test Valid AAD
  Data = ecrypto_aead:decrypt(Key,IV,EncData,AAD,proplists:get_value(params,Config)),
  ok.

%%--------------------------------------------------------------------

test_encrypt_decrypt_aes192_cbc_sha384(suite) ->
  [];
test_encrypt_decrypt_aes192_cbc_sha384({init, Config}) ->
  Params = ecrypto_aead:aes192_cbc_sha384(),
  Key = <<1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6>>,
  [{key,Key},{params,Params}|Config];
test_encrypt_decrypt_aes192_cbc_sha384({terminate, _Config}) ->
  ok;
test_encrypt_decrypt_aes192_cbc_sha384(Config) when is_list(Config) ->
  Key = proplists:get_value(key,Config),
  Data = <<"123456789012345">>,

  EncData = ecrypto_aead:encrypt(Key,Data,<<>>,proplists:get_value(params,Config)),
  ?assertEqual(56,size(EncData)),
  Data = ecrypto_aead:decrypt(Key,EncData,<<>>,proplists:get_value(params,Config)),
  ok.

test_encrypt_decrypt_aes256_cbc_sha512(suite) ->
  [];
test_encrypt_decrypt_aes256_cbc_sha512({init, Config}) ->
  Params = ecrypto_aead:aes256_cbc_sha512(),
  Key = <<1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6>>,
  [{key,Key},{params,Params}|Config];
test_encrypt_decrypt_aes256_cbc_sha512({terminate, _Config}) ->
  ok;
test_encrypt_decrypt_aes256_cbc_sha512(Config) when is_list(Config) ->
  Key = proplists:get_value(key,Config),
  Data = <<"123456789012345">>,

  EncData = ecrypto_aead:encrypt(Key,Data,<<>>,proplists:get_value(params,Config)),
  ?assertEqual(64,size(EncData)),
  Data = ecrypto_aead:decrypt(Key,EncData,<<>>,proplists:get_value(params,Config)),
  ok.
