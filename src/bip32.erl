-module(bip32).

-export([
         ckd_priv/2,
         ckd_pub/2,
         neuter/1,
         harden/1,
         key_id/1,
         fingerprint/1,
         serialize_priv/5,
         serialize_pub/5,
         deserialize_priv/1,
         deserialize_pub/1,
         seed/0,
         ser_P/1,
         master_key/1
        ]).

-define(N, 16#FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141).
-define(HARDENED_INDEX_START, 16#80000000).
-define(SEED_SIZE, 64).


point(P) ->
    PrivKey = <<P:256>>,
    {ok, PubKey} = libsecp256k1:ec_pubkey_create(PrivKey, uncompressed),
    coordinate_pair(PubKey).


ser_32(I) ->
    <<I:32>>.


ser_256(P) ->
    <<P:256>>.


ser_P({X, Y}) ->
    Header = if Y rem 2 == 0 -> <<2:8>>; true -> <<3:8>> end,
    X_ = ser_256(X),
    <<Header/binary, X_/binary>>.


parse_256(P) ->
    <<N:256>> = P,
    N.


ckd_priv({K_par, C_par}, Idx) ->
    I = case Idx >= ?HARDENED_INDEX_START of
        true  -> crypto:mac(hmac, sha512, C_par, [<<0:8>>, ser_256(K_par), ser_32(Idx)]);
        false -> crypto:mac(hmac, sha512, C_par, [ser_P(point(K_par)), ser_32(Idx)])
    end,
    {I_L, I_R} = split(I),
    I_L_ = parse_256(I_L),
    if I_L_ >= ?N -> throw(invalid_key); true -> ok end,
    K_i = (I_L_ + K_par) rem ?N,
    if K_i == 0 -> throw(invalid_key); true -> ok end,
    C_i = I_R,
    {K_i, C_i}.


ckd_pub({_, _}, Idx) when Idx >= ?HARDENED_INDEX_START ->
    throw(undefined_for_hardened_child);

ckd_pub({K_par, C_par}, Idx) ->
    I = crypto:mac(hmac, sha512, C_par, [ser_P(K_par), ser_32(Idx)]),
    {I_L, I_R} = split(I),
    I_L_ = parse_256(I_L),
    if I_L_ >= ?N -> throw(invalid_key); true -> ok end,
    K_i = try
        {ok, K_i_} = libsecp256k1:ec_pubkey_tweak_add(uncompressed_pubkey(K_par), I_L),
        ok = libsecp256k1:ec_pubkey_verify(K_i_),  % this might be superfluous
        coordinate_pair(K_i_)
    catch
        _:_ -> throw(invalid_key)
    end,
    C_i = I_R,
    {K_i, C_i}.


neuter({K_priv, C}) ->
    {point(K_priv), C}.


harden(Idx) ->
    case Idx >= ?HARDENED_INDEX_START of
        true  -> Idx;
        false -> Idx + ?HARDENED_INDEX_START
    end.


key_id(K_pub) ->
    crypto:hash(ripemd160, crypto:hash(sha256, ser_P(K_pub))).


fingerprint(K_pub) ->
    <<Fingerprint:32, _/binary>> = key_id(K_pub),
    Fingerprint.


serialize_priv({K, C}, Idx, Depth, Version, ParentFingerprint) ->
    K_ = ser_256(K),
    serialize(Version, Depth, ParentFingerprint, ser_32(Idx), C, <<0:8, K_/binary>>).


serialize_pub({K, C}, Idx, Depth, Version, ParentFingerprint) ->
    serialize(Version, Depth, ParentFingerprint, ser_32(Idx), C, ser_P(K)).


serialize(Version, Depth, ParentFingerprint, ChildNumber, ChainCode, KeyData) ->
    <<Version:32, Depth:8, ParentFingerprint:32, ChildNumber:4/binary, ChainCode:32/binary, KeyData:33/binary>>.


deserialize_priv(<<Version:32, Depth:8, ParentFingerprint:32, ChildIndex:32, ChainCode:32/binary, KeyData:33/binary>>) ->
    try
        <<0:8, Key:32/binary>> = KeyData,
        %ok = libsecp256k1:ec_seckey_verify(Key),  this NIF causes corruption of Key
        PrivateKey = parse_256(Key),
        {PrivateKey, ChainCode, ChildIndex, Depth, Version, ParentFingerprint}
    catch
        _:_ -> throw(invalid_key)
    end.


deserialize_pub(<<Version:32, Depth:8, ParentFingerprint:32, ChildIndex:32, ChainCode:32/binary, KeyData:33/binary>>) ->
    try
        {ok, Key} = libsecp256k1:ec_pubkey_decompress(KeyData),
        ok = libsecp256k1:ec_pubkey_verify(Key),  % this might be superfluous
        PublicKey = coordinate_pair(Key),
        {PublicKey, ChainCode, ChildIndex, Depth, Version, ParentFingerprint}
    catch
        _:_ -> throw(invalid_key)
    end.


seed() ->
    crypto:strong_rand_bytes(?SEED_SIZE).


master_key(S) ->
    I = crypto:mac(hmac, sha512, <<"Bitcoin seed">>, S),
    {I_L, I_R} = split(I),
    I_L_ = parse_256(I_L),
    if I_L_ == 0 orelse I_L_ >= ?N -> throw(invalid_key); true -> ok end,
    K = I_L_,
    C = I_R,
    {K, C}.


split(I) ->
    I_L = binary:part(I, 0, 32),
    I_R = binary:part(I, 32, 32),
    {I_L, I_R}.


coordinate_pair(<<4:8, X:256, Y:256>>) ->
    {X, Y}.


uncompressed_pubkey({X, Y}) ->
    <<4:8, X:256, Y:256>>.
