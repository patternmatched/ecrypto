%%% Copyright   : (C) 2003-2010 Pattern Matched Technologies (Pty) Ltd. 
%%% File        : ecrypto_utils.erl
%%% Author      : Andre du Preez <>
%%% Description : 
%%% Created     : 18 Jan 2018 by Andre du Preez <>

-module(ecrypto_utils).

-export([pkcs7_pad/2, pkcs7_unpad/1]).

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
