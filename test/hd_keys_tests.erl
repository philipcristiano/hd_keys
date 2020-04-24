-module(hd_keys_tests).

-include_lib("eunit/include/eunit.hrl").


test_vector_1_test_() ->
    Seed = <<16#00, 16#01, 16#02, 16#03, 16#04, 16#05, 16#06, 16#07, 16#08, 16#09, 16#0a, 16#0b, 16#0c, 16#0d, 16#0e, 16#0f>>,
    Master = hd_keys:master_private_key(Seed, 16#0488ade4),
    Chain1 = hd_keys:derive_child_key(Master, <<"m">>),
    Chain2 = hd_keys:derive_child_key(Master, <<"m/0H">>),
    Chain3 = hd_keys:derive_child_key(Master, <<"m/0H/1">>),
    Chain4 = hd_keys:derive_child_key(Master, <<"m/0H/1/2H">>),
    Chain5 = hd_keys:derive_child_key(Master, <<"m/0H/1/2H/2">>),
    Chain6 = hd_keys:derive_child_key(Master, <<"m/0H/1/2H/2/1000000000">>),
    [
     ?_assertEqual(<<"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8">>, hd_keys:export(hd_keys:neuter(Chain1))),
     ?_assertEqual(<<"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi">>, hd_keys:export(Chain1)),
     ?_assertEqual(<<"xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw">>, hd_keys:export(hd_keys:neuter(Chain2))),
     ?_assertEqual(<<"xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7">>, hd_keys:export(Chain2)),
     ?_assertEqual(<<"xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ">>, hd_keys:export(hd_keys:neuter(Chain3))),
     ?_assertEqual(<<"xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs">>, hd_keys:export(Chain3)),
     ?_assertEqual(<<"xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5">>, hd_keys:export(hd_keys:neuter(Chain4))),
     ?_assertEqual(<<"xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM">>, hd_keys:export(Chain4)),
     ?_assertEqual(<<"xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV">>, hd_keys:export(hd_keys:neuter(Chain5))),
     ?_assertEqual(<<"xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334">>, hd_keys:export(Chain5)),
     ?_assertEqual(<<"xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy">>, hd_keys:export(hd_keys:neuter(Chain6))),
     ?_assertEqual(<<"xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76">>, hd_keys:export(Chain6))
    ].


test_vector_2_test_() ->
    Seed = <<16#ff, 16#fc, 16#f9, 16#f6, 16#f3, 16#f0, 16#ed, 16#ea, 16#e7, 16#e4, 16#e1, 16#de, 16#db, 16#d8, 16#d5, 16#d2, 16#cf, 16#cc, 16#c9, 16#c6, 16#c3, 16#c0, 16#bd, 16#ba, 16#b7, 16#b4, 16#b1, 16#ae, 16#ab, 16#a8, 16#a5, 16#a2, 16#9f, 16#9c, 16#99, 16#96, 16#93, 16#90, 16#8d, 16#8a, 16#87, 16#84, 16#81, 16#7e, 16#7b, 16#78, 16#75, 16#72, 16#6f, 16#6c, 16#69, 16#66, 16#63, 16#60, 16#5d, 16#5a, 16#57, 16#54, 16#51, 16#4e, 16#4b, 16#48, 16#45, 16#42>>,
    Master = hd_keys:master_private_key(Seed, 16#0488ade4),
    Chain1 = hd_keys:derive_child_key(Master, <<"m">>),
    Chain2 = hd_keys:derive_child_key(Master, <<"m/0">>),
    Chain3 = hd_keys:derive_child_key(Master, <<"m/0/2147483647H">>),
    Chain4 = hd_keys:derive_child_key(Master, <<"m/0/2147483647H/1">>),
    Chain5 = hd_keys:derive_child_key(Master, <<"m/0/2147483647H/1/2147483646H">>),
    Chain6 = hd_keys:derive_child_key(Master, <<"m/0/2147483647H/1/2147483646H/2">>),
    [
     ?_assertEqual(<<"xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB">>, hd_keys:export(hd_keys:neuter(Chain1))),
     ?_assertEqual(<<"xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U">>, hd_keys:export(Chain1)),
     ?_assertEqual(<<"xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH">>, hd_keys:export(hd_keys:neuter(Chain2))),
     ?_assertEqual(<<"xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt">>, hd_keys:export(Chain2)),
     ?_assertEqual(<<"xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a">>, hd_keys:export(hd_keys:neuter(Chain3))),
     ?_assertEqual(<<"xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9">>, hd_keys:export(Chain3)),
     ?_assertEqual(<<"xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon">>, hd_keys:export(hd_keys:neuter(Chain4))),
     ?_assertEqual(<<"xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef">>, hd_keys:export(Chain4)),
     ?_assertEqual(<<"xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL">>, hd_keys:export(hd_keys:neuter(Chain5))),
     ?_assertEqual(<<"xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc">>, hd_keys:export(Chain5)),
     ?_assertEqual(<<"xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt">>, hd_keys:export(hd_keys:neuter(Chain6))),
     ?_assertEqual(<<"xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j">>, hd_keys:export(Chain6))
    ].


test_vector_3_test_() ->
    Seed = <<16#4b, 16#38, 16#15, 16#41, 16#58, 16#3b, 16#e4, 16#42, 16#33, 16#46, 16#c6, 16#43, 16#85, 16#0d, 16#a4, 16#b3, 16#20, 16#e4, 16#6a, 16#87, 16#ae, 16#3d, 16#2a, 16#4e, 16#6d, 16#a1, 16#1e, 16#ba, 16#81, 16#9c, 16#d4, 16#ac, 16#ba, 16#45, 16#d2, 16#39, 16#31, 16#9a, 16#c1, 16#4f, 16#86, 16#3b, 16#8d, 16#5a, 16#b5, 16#a0, 16#d0, 16#c6, 16#4d, 16#2e, 16#8a, 16#1e, 16#7d, 16#14, 16#57, 16#df, 16#2e, 16#5a, 16#3c, 16#51, 16#c7, 16#32, 16#35, 16#be>>,
    Master = hd_keys:master_private_key(Seed, 16#0488ade4),
    Chain1 = hd_keys:derive_child_key(Master, <<"m">>),
    Chain2 = hd_keys:derive_child_key(Master, <<"m/0H">>),
    [
     ?_assertEqual(<<"xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13">>, hd_keys:export(hd_keys:neuter(Chain1))),
     ?_assertEqual(<<"xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6">>, hd_keys:export(Chain1)),
     ?_assertEqual(<<"xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y">>, hd_keys:export(hd_keys:neuter(Chain2))),
     ?_assertEqual(<<"xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L">>, hd_keys:export(Chain2))
    ].
