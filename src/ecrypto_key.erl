%%% Copyright   : (C) 2003-2019 Pattern Matched Technologies (Pty) Ltd.
%%% Description : 
%%% Created     : 13 Sep 2019 by Andre du Preez <>
%%==========================================================================================
-module(ecrypto_key).
%%==========================================================================================
-export([kdf2/4]).
%%==========================================================================================
%% IEEEE P 1683a KDF2
%%==========================================================================================
-define(MAX_COUNTER,4294967296).

kdf2(SharedSecret,ExtraData,KeyOutputSize,HashAlgoritm) when is_binary(SharedSecret),
							     is_binary(ExtraData),
							     is_integer(KeyOutputSize),
							     is_atom(HashAlgoritm) ->
  HashSize = ecrypto_utils:hash_size(HashAlgoritm),
  RepCount = (KeyOutputSize + HashSize - 1) div HashSize,
  F = fun(Counter,Results) ->
	  Hash = crypto:hash(HashAlgoritm,<<SharedSecret/binary,(Counter rem ?MAX_COUNTER):32,ExtraData/binary>>),
	  <<Results/binary,Hash/binary>>
      end,
  ecrypto_utils:trunc_bin(lists:foldl(F,<<>>,lists:seq(1,RepCount)),KeyOutputSize).

