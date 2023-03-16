-module(hd_keys).

-export([
         master_private_key/2,
         derive_child_key/2,
         derive_private_child_key/2,
         derive_public_child_key/2,
         neuter/1,
         fingerprint/1,
         serialize/1,
         serialize_public_key/1,
         export/1,
         import/1
        ]).


master_private_key(Seed, Version) ->
    {PrivateKey, ChainCode} = bip32:master_key(Seed),
    #{private_key        => PrivateKey,
      chain_code         => ChainCode,
      child_index        => 0,
      depth              => 0,
      version            => Version,
      parent_fingerprint => 0}.


derive_child_key(MasterKey, <<"m",_/binary>> = Path) ->
    derive_child_key(MasterKey, Path, fun derive_private_child_key/2);

derive_child_key(MasterKey, <<"M",_/binary>> = Path) ->
    derive_child_key(neuter(MasterKey), Path, fun derive_public_child_key/2).


derive_child_key(MasterKey, Path, DeriveFun) ->
    Components = binary:split(Path, <<"/">>, [global]),
    lists:foldl(fun(Component, ExtendedKey) ->
                        ChildIndex = child_index(Component),
                        DeriveFun(ExtendedKey, ChildIndex)
                end,
                MasterKey,
                tl(Components)).


child_index(PathComponent) ->
    case binary:last(PathComponent) of
        C when C=:=$H; C=:=$h; C=:=$' ->
            bip32:harden(binary_to_integer(binary:part(PathComponent, 0, size(PathComponent)-1)));
        _ ->
            binary_to_integer(PathComponent)
    end.


derive_private_child_key(#{private_key:=PrivateKey, chain_code:=ChainCode, depth:=Depth, version:=Version} = ParentKey, ChildIndex) ->
    {ChildPrivateKey, ChildChainCode} = bip32:ckd_priv({PrivateKey, ChainCode}, ChildIndex),
    #{private_key        => ChildPrivateKey,
      chain_code         => ChildChainCode,
      child_index        => ChildIndex,
      depth              => Depth + 1,
      version            => Version,
      parent_fingerprint => fingerprint(ParentKey)}.


derive_public_child_key(#{public_key:=PublicKey, chain_code:=ChainCode, depth:=Depth, version:=Version} = ParentKey, ChildIndex) ->
    {ChildPublicKey, ChildChainCode} = bip32:ckd_pub({PublicKey, ChainCode}, ChildIndex),
    #{public_key         => ChildPublicKey,
      chain_code         => ChildChainCode,
      child_index        => ChildIndex,
      depth              => Depth + 1,
      version            => Version,
      parent_fingerprint => fingerprint(ParentKey)};

derive_public_child_key(#{private_key:=PrivateKey, chain_code:=ChainCode, depth:=Depth, version:=Version} = ParentKey, ChildIndex) ->
    {ChildPublicKey, ChildChainCode} = bip32:neuter(bip32:ckd_priv({PrivateKey, ChainCode}, ChildIndex)),
    #{public_key         => ChildPublicKey,
      chain_code         => ChildChainCode,
      child_index        => ChildIndex,
      depth              => Depth + 1,
      version            => public_version(Version),
      parent_fingerprint => fingerprint(ParentKey)}.


neuter(#{private_key:=PrivateKey, version:=Version} = ExtendedKey) ->
    {PublicKey, _} = bip32:neuter({PrivateKey, 0}),
    maps:remove(private_key, ExtendedKey#{public_key=>PublicKey, version:=public_version(Version)});

neuter(#{public_key:=_} = ExtendedKey) ->
    ExtendedKey.


fingerprint(ExtendedKey) ->
    #{public_key:=PublicKey} = neuter(ExtendedKey),
    bip32:fingerprint(PublicKey).


serialize(#{private_key:=PrivateKey, chain_code:=ChainCode, child_index:=ChildIndex, depth:=Depth, version:=Version, parent_fingerprint:=ParentFingerprint}) ->
    bip32:serialize_priv({PrivateKey, ChainCode}, ChildIndex, Depth, Version, ParentFingerprint);

serialize(#{public_key:=PublicKey, chain_code:=ChainCode, child_index:=ChildIndex, depth:=Depth, version:=Version, parent_fingerprint:=ParentFingerprint}) ->
    bip32:serialize_pub({PublicKey, ChainCode}, ChildIndex, Depth, Version, ParentFingerprint).

serialize_public_key(#{public_key:=PublicKey}) ->
    bip32:ser_P(PublicKey).

export(ExtendedKey) ->
    base58_utils:version_encode_check(serialize(ExtendedKey)).


import(EncodedKey) ->
    SerializedKey = base58_utils:version_decode_check(EncodedKey),
    case catch bip32:deserialize_priv(SerializedKey) of
        invalid_key ->
            {PublicKey, ChainCode, ChildIndex, Depth, Version, ParentFingerprint} = bip32:deserialize_pub(SerializedKey),
            #{public_key         => PublicKey,
              chain_code         => ChainCode,
              child_index        => ChildIndex,
              depth              => Depth,
              version            => Version,
              parent_fingerprint => ParentFingerprint};
        Result ->
            {PrivateKey, ChainCode, ChildIndex, Depth, Version, ParentFingerprint} = Result,
            #{private_key        => PrivateKey,
              chain_code         => ChainCode,
              child_index        => ChildIndex,
              depth              => Depth,
              version            => Version,
              parent_fingerprint => ParentFingerprint}
    end.


% From https://github.com/satoshilabs/slips/blob/master/slip-0132.md
public_version(16#0488ade4) -> 16#0488b21e;
public_version(16#049d7878) -> 16#049d7cb2;
public_version(16#04b2430c) -> 16#04b24746;
public_version(16#0295b005) -> 16#0295b43f;
public_version(16#02aa7a99) -> 16#02aa7ed3;
public_version(16#04358394) -> 16#043587cf;
public_version(16#044a4e28) -> 16#044a5262;
public_version(16#045f18bc) -> 16#045f1cf6;
public_version(16#024285b5) -> 16#024289ef;
public_version(16#02575048) -> 16#02575483;
public_version(16#019d9cfe) -> 16#019da462;
public_version(16#01b26792) -> 16#01b26ef6;
public_version(16#0436ef7d) -> 16#0436f6e1;
public_version(16#03e25945) -> 16#03e25d7e.
