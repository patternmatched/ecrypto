%%% Copyright   : (C) 2003-2010 Pattern Matched Technologies (Pty) Ltd. 
%%% File        : ecrypto_utils.erl
%%% Author      : Andre du Preez <>
%%% Description : 
%%% Created     : 18 Jan 2018 by Andre du Preez <>

-module(ecrypto_utils).

-export([
	 pkcs7_pad/2, pkcs7_unpad/1,
	 ec_pubkey_der_decode/2, ec_pubkey_der_encode/2
	]).

pkcs7_pad(Data,Size) ->
  PadLen = case size(Data) rem Size of
	     0 -> Size;
	     P -> (Size - P)
	   end,
  PadBytes = list_to_binary(lists:duplicate(PadLen,PadLen)),
  <<Data/binary,PadBytes/binary>>.

pkcs7_unpad(Data) ->
  PadLength = binary:last(Data),
  DataLength = size(Data)-PadLength,
  <<LData:DataLength/binary,_/binary>> = Data,
  LData.

ec_pubkey_der_decode(PubKey,_CurveName) ->
  {'SubjectPublicKeyInfo',_,PubKeyRaw} = public_key:der_decode('SubjectPublicKeyInfo',PubKey),
  PubKeyRaw.

ec_pubkey_der_encode(PubKey,CurveName) ->
  public_key:der_encode('SubjectPublicKeyInfo',{'SubjectPublicKeyInfo',algo_id(CurveName),PubKey}).
  
algo_id(secp256r1) -> 
  {'AlgorithmIdentifier',{1,2,840,10045,2,1},<<6,8,42,134,72,206,61,3,1,7>>};
algo_id(CurveName) ->
  throw({ec_curve_not_supported,[{curvename,CurveName}]}).
