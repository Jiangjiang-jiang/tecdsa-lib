/*
 * BICYCL Implements CryptographY in CLass groups
 * Copyright (C) 2024  Cyril Bouvier <cyril.bouvier@lirmm.fr>
 *                     Guilhem Castagnos <guilhem.castagnos@math.u-bordeaux.fr>
 *                     Laurent Imbert <laurent.imbert@lirmm.fr>
 *                     Fabien Laguillaumie <fabien.laguillaumie@lirmm.fr>
 *                     Quentin Combal <quentin.combal@lirmm.fr>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#ifndef BICYCL_TWOPARTY_ECDSA_INL
#define BICYCL_TWOPARTY_ECDSA_INL

#include "twoParty_ECDSA.hpp"

namespace BICYCL
{
  //////////////////////////////////////////////////////////////////////////////
  //    ___ _      ___   _____ ___   _
  //   | _ \ |    /_\ \ / / __| _ \ / |
  //   |  _/ |__ / _ \ V /| _||   / | |
  //   |_| |____/_/ \_\_| |___|_|_\ |_|
  //
  inline
  TwoPartyECDSA::Player1::Player1(const TwoPartyECDSA & Context2pECDSA)
    : Q1_{Context2pECDSA.ec_group_},
      R1_{Context2pECDSA.ec_group_},
      public_key_{Context2pECDSA.ec_group_},
      proof_ckey_{Context2pECDSA.ec_group_},
      zk_com_proof_{Context2pECDSA.ec_group_}
  {
    // Nothing to do
  }

  inline const ECPoint & TwoPartyECDSA::Player1::Q1() const
  {
    return Q1_;
  }

  inline const ECPoint & TwoPartyECDSA::Player1::R1() const
  {
    return R1_;
  }

  inline const ECPoint & TwoPartyECDSA::Player1::public_key() const
  {
    return public_key_;
  }

  inline const TwoPartyECDSA::Commitment & TwoPartyECDSA::Player1::commit() const
  {
    return commit_;
  }

  inline const TwoPartyECDSA::CommitmentSecret &
  TwoPartyECDSA::Player1::commit_secret() const
  {
    return commit_secret_;
  }

  inline const CL_HSMqk::PublicKey & TwoPartyECDSA::Player1::pkcl() const
  {
    return pkcl_;
  }

  inline const CL_HSMqk::CipherText & TwoPartyECDSA::Player1::Ckey() const
  {
    return Ckey_;
  }

  inline const ECNIZKProof & TwoPartyECDSA::Player1::zk_com_proof() const
  {
    return zk_com_proof_;
  }

  inline const CLDLZKProof & TwoPartyECDSA::Player1::proof_ckey() const
  {
    return proof_ckey_;
  }

  inline
  void TwoPartyECDSA::Player1::KeygenPart1(const TwoPartyECDSA & Context2pECDSA,
                                           RandGen & randgen)
  {
    // Generate x1 from OpenSSL randomizer
    x1_ = Context2pECDSA.ec_group_.random_mod_order(randgen);
    // Compute Q1 <- [x1] P
    Context2pECDSA.ec_group_.scal_mul_gen(Q1_, x1_);

    // Compute proof of x1 knowledge
    zk_com_proof_
        = ECNIZKProof(Context2pECDSA.ec_group_, Context2pECDSA.H_, randgen, x1_, Q1_);

    // Compute commitment + commitment secret
    std::tie(commit_, commit_secret_) = Context2pECDSA.commit(randgen, zk_com_proof_);
  }

  inline
  void TwoPartyECDSA::Player1::KeygenPart3(const TwoPartyECDSA & Context2pECDSA,
                                           RandGen & randgen,
                                           const ECPoint & Q2,
                                           const ECNIZKProof & proof_x2)
  {
    // Verify ZK proof
    if (false
        == proof_x2.verify(Context2pECDSA.ec_group_, Context2pECDSA.H_, Q2))
    {
      throw ProtocolAbortError("could not verify ZK-proof of x2 knowledge");
    }

    // Generate CL_HSM keys
    skcl_ = Context2pECDSA.CL_HSMq_.keygen(randgen); // Secret key
    pkcl_ = Context2pECDSA.CL_HSMq_.keygen(skcl_);     // Public key from secret key

    // Encrypt x1 into Ckey
    Mpz random = Context2pECDSA.CL_HSMq_.encrypt_randomness_bound();
    CL_HSMqk::ClearText x1ClearText(Context2pECDSA.CL_HSMq_, Mpz(x1_));

#ifdef BICYCL_WITH_PTHREADS
    // Ckey computation is done in a separate thread
    auto compute_ckey = [this, &Context2pECDSA, x1ClearText, random] (CL_HSMqk::CipherText & ckey) {
      ckey = CL_HSMqk::CipherText(
        Context2pECDSA.CL_HSMq_, pkcl_, x1ClearText, random);
    };
    std::thread th(compute_ckey, std::ref(Ckey_));

    // Compute proof of Ckey's plaintext knowledge
    // Provide thread reference to proof constructor, so that the thread can be
    // joined when Ckey value is needed
    proof_ckey_ = CLDLZKProof(Context2pECDSA.H_,
                              Context2pECDSA.ec_group_,
                              x1_,
                              Q1_,
                              Context2pECDSA.CL_HSMq_,
                              pkcl_,
                              Ckey_,
                              random,
                              randgen,
                              th);
#else
    Ckey_ = CL_HSMqk::CipherText(
        Context2pECDSA.CL_HSMq_, pkcl_, x1ClearText, random);

    // Compute proof of Ckey's plaintext knowledge
    proof_ckey_ = CLDLZKProof(Context2pECDSA.H_,
                              Context2pECDSA.ec_group_,
                              x1_,
                              Q1_,
                              Context2pECDSA.CL_HSMq_,
                              pkcl_,
                              Ckey_,
                              random,
                              randgen);
#endif


    // Compute Q
    Context2pECDSA.ec_group_.scal_mul(public_key_, x1_, Q2);
  }

  inline
  void TwoPartyECDSA::Player1::SignPart1(const TwoPartyECDSA & Context2pECDSA,
                                         RandGen & randgen, const Mpz & sid)
  {
    // Generate k1 from OpenSSL randomizer
    k1_ = Context2pECDSA.ec_group_.random_mod_order(randgen);
    // Compute R1 <- [k1] P
    Context2pECDSA.ec_group_.scal_mul_gen(R1_, k1_);

    // Compute proof of k1 knowledge
    Mpz sid1;
    Mpz::mulby2(sid1, sid);
    sid1.setbit(0);
    zk_com_proof_ = ECNIZKProof(
        Context2pECDSA.ec_group_, Context2pECDSA.H_, randgen, k1_, R1_, sid1);

    // Compute commitment + commitment secret
    std::tie(commit_, commit_secret_)
        = Context2pECDSA.commit(randgen, zk_com_proof_);
  }

  inline TwoPartyECDSA::Player1::PresignData
  TwoPartyECDSA::Player1::SignPart3(const TwoPartyECDSA & Context2pECDSA,
                                    const ECPoint & R2,
                                    const ECNIZKProof & proof_k2,
                                    const Mpz & sid)
  {
    // Verify ZK proof
    Mpz sid2;
    Mpz::mulby2(sid2, sid);
    if (false
        == proof_k2.verify(Context2pECDSA.ec_group_, Context2pECDSA.H_, R2, sid2))
    {
      throw ProtocolAbortError("could not verify ZK-proof of k2 knowledge");
    }

    // Compute R <- [k1] R2, and extract r
    ECPoint R(Context2pECDSA.ec_group_);

    Context2pECDSA.ec_group_.scal_mul(R, k1_, R2);
    Context2pECDSA.ec_group_.x_coord_of_point(r_, R); // r <- Rx

    return PresignData{k1_, r_};
  }

  inline ECSignature
  TwoPartyECDSA::Player1::SignPart5(const TwoPartyECDSA & Context2pECDSA,
                                    const HashAlgo::Digest & m,
                                    const CL_HSMqk::CipherText & C3)
  {
    return SignPart5(Context2pECDSA, m, C3, {k1_, r_});
  }

  inline ECSignature
  TwoPartyECDSA::Player1::SignPart5(const TwoPartyECDSA & Context2pECDSA,
                                    const HashAlgo::Digest & m,
                                    const CL_HSMqk::CipherText & C3,
                                    const PresignData & presign_data)
  {
    const ECGroup & E = Context2pECDSA.ec_group_;

    const BN & k1 = presign_data[0];
    const BN & r = presign_data[1];

    // Decrypt C3 using secret key
    Mpz alpha = Context2pECDSA.CL_HSMq_.decrypt(skcl_, C3);

    // s <-- alpha * k1^-1 = Dec(skcl, C3) * k1^-1
    BN temp, s;
    Context2pECDSA.ec_group_.inverse_mod_order(temp, k1);
    Context2pECDSA.ec_group_.mul_mod_order(s, temp, BN(alpha));

    // s <-- min(s, q-s)
    Context2pECDSA.ec_group_.neg_mod_order(temp, s); // temp = q-s
    if (temp <= s)
    {
      s = temp;
    }
    ECSignature sig{r,s};

    if (not sig.verify(E, public_key_, m))
      throw ProtocolAbortError("could not verify the output signature");

    return ECSignature(r, s);
  }

////////////////////////////////////////////////////////////////////////////////
//     ___   __  __ _ _          ___            _
//    / _ \ / _|/ _| (_)_ _  ___| _ \_ _ ___ __(_)__ _ _ _
//   | (_) |  _|  _| | | ' \/ -_)  _/ '_/ -_|_-< / _` | ' \.
//    \___/|_| |_| |_|_|_||_\___|_| |_| \___/__/_\__, |_||_|
//                                               |___/
////////////////////////////////////////////////////////////////////////////////

  inline TwoPartyECDSA::Player2::PresignData::PresignData(
      const TwoPartyECDSA & ctx,
      const CLPublicKey pkcl,
      const CLCipherText & ckey_x2,
      const Mpz & r,
      const Mpz k2,
      const Mpz t)
  {
    const ECGroup & E = ctx.ec_group_;
    const CL_HSMqk & CL = ctx.CL_HSMq_;

    Mpz::mod_inverse(k2_inv_, k2, E.order());
    Mpz exp;
    Mpz::mul(exp, k2_inv_, r);
    Mpz::mod(exp, exp, E.order());

#ifdef BICYCL_WITH_PTHREADS
    QFI f1, f2, f3, f4;

    void (ClassGroup::*nupow_ptr)(QFI &, const QFI &, const Mpz &) const
        = &ClassGroup::nupow;
    /* f1 <-- {Ckey_1^{x_2}} ^ {k_2^{-1} * r} */
    std::thread th_f1{nupow_ptr,
                      std::cref(CL.Cl_G()),
                      std::ref(f1),
                      std::cref(ckey_x2.c1()),
                      std::cref(exp)};
    /* f2 <-- {Ckey_2^{x_2}} ^ {k_2^{-1} * r} */
    std::thread th_f2{nupow_ptr,
                      std::cref(CL.Cl_G()),
                      std::ref(f2),
                      std::cref(ckey_x2.c2()),
                      std::cref(exp)};

    /* f3 <-- gq^{t} */
    auto  power_of_h_ptr = &CL_HSMqk::power_of_h;
    std::thread th_f3{
        power_of_h_ptr, std::cref(CL), std::ref(f3), std::cref(t)};

    /* f4 <-- pkcl^{t} */
    pkcl.exponentiation(CL, f4, t);

    /* C31 <-- f1 * f3 = Ckey_1^{x_2 * k_2^{-1} * r} * gq^{t} */
    th_f1.join();
    th_f3.join();
    CL.Cl_G().nucomp(C31_, f1, f3);

    /* C32p <-- f2 * f4 = Ckey_1^{x_2 * k_2^{-1} * r} * pkcl^{t} */
    th_f2.join();
    CL.Cl_G().nucomp(C32p_, f2, f4);

#else
    QFI f_temp;
    /* f_temp <-- {Ckey_1^{x_2}} ^ {k_2^{-1} * r} */
    CL.Cl_G().nupow(f_temp, ckey_x2.c1(), exp);
    /* C31 <-- f_temp * gq^{t} = Ckey_1^{x_2 * k_2^{-1} * r} * gq^{t} */
    CL.power_of_h(C31_, t);
    CL.Cl_G().nucomp(C31_, C31_, f_temp);

    /* f_temp <-- {Ckey_2^{x_2}} ^ {k_2^{-1} * r} */
    CL.Cl_G().nupow(f_temp, ckey_x2.c2(), exp);
    /* C32p <-- f_temp * pkcl^{t} = Ckey_1^{x_2 * k_2^{-1} * r} * pkcl^{t} */
    pkcl.exponentiation(CL, C32p_, t);
    CL.Cl_G().nucomp(C32p_, C32p_, f_temp);

#endif
  }

  inline
  TwoPartyECDSA::Player2::PresignData::PresignData(const TwoPartyECDSA & ctx,
                                            const CLPublicKey pkcl,
                                            const CLCipherText & ckey_x2,
                                            const Mpz & r,
                                            const Mpz k2,
                                            RandGen & randgen)
    : PresignData(ctx,
                   pkcl,
                   ckey_x2,
                   r,
                   k2,
                   randgen.random_mpz(ctx.CL_HSMq_.encrypt_randomness_bound()))
  {
  }

  //////////////////////////////////////////////////////////////////////////////
  //    ___ _      ___   _____ ___   ___
  //   | _ \ |    /_\ \ / / __| _ \ |_  )
  //   |  _/ |__ / _ \ V /| _||   /  / /
  //   |_| |____/_/ \_\_| |___|_|_\ /___|
  //
  inline
  TwoPartyECDSA::Player2::Player2(const TwoPartyECDSA & Context2pECDSA)
    : Q2_{Context2pECDSA.ec_group_},
      R2_{Context2pECDSA.ec_group_},
      public_key_{Context2pECDSA.ec_group_},
      zk_proof_{Context2pECDSA.ec_group_}
  {
    // Nothing to do
  }

  inline const ECPoint & TwoPartyECDSA::Player2::Q2() const
  {
    return Q2_;
  }

  inline const ECPoint & TwoPartyECDSA::Player2::R2() const
  {
    return R2_;
  }

  inline const ECPoint & TwoPartyECDSA::Player2::public_key() const
  {
    return public_key_;
  }

  inline const CL_HSMqk::PublicKey & TwoPartyECDSA::Player2::pkcl() const
  {
    return pkcl_;
  }

  inline const CL_HSMqk::CipherText & TwoPartyECDSA::Player2::C3() const
  {
    return C3_;
  }

  inline const ECNIZKProof & TwoPartyECDSA::Player2::zk_proof() const
  {
    return zk_proof_;
  }

  inline
  void TwoPartyECDSA::Player2::KeygenPart2(const TwoPartyECDSA & Context2pECDSA,
                                           RandGen & randgen,
                                           const Commitment & commit_Q1)
  {
    // Generate x2 from OpenSSL randomizer
    x2_ = Context2pECDSA.ec_group_.random_mod_order(randgen);
    // Compute Q2 <- [x1] P
    Context2pECDSA.ec_group_.scal_mul_gen(Q2_, x2_);

    // Store commitment
    commit_ = commit_Q1;

    // Compute proof of x2 knowledge
    zk_proof_ = ECNIZKProof(
        Context2pECDSA.ec_group_, Context2pECDSA.H_, randgen, x2_, Q2_);
  }

  inline
  void TwoPartyECDSA::Player2::KeygenPart4(
      const TwoPartyECDSA & Context2pECDSA,
      const ECPoint & Q1,
      const CL_HSMqk::CipherText & Ckey,
      const CL_HSMqk::PublicKey & pk,
      const TwoPartyECDSA::CommitmentSecret commit_secret,
      const ECNIZKProof & proof_x1,
      const CLDLZKProof & proof_ckey)
  {
    // Check commitment of proof matches
    if (false == Context2pECDSA.open(commit_, proof_x1, commit_secret))
    {
      throw ProtocolAbortError(
          "could not verify commited value of ZK-proof (in KeyGen)");
    }

    // Verify ZK proof
    if (false
        == proof_x1.verify(Context2pECDSA.ec_group_, Context2pECDSA.H_, Q1))
    {
      throw ProtocolAbortError("could not verify ZK-proof of x1 knowledge");
    }

    // Verify ZK proof
    if (false
        == proof_ckey.verify(Context2pECDSA.H_,
                             Context2pECDSA.ec_group_,
                             Q1,
                             Context2pECDSA.CL_HSMq_,
                             pk,
                             Ckey))
    {
      throw ProtocolAbortError("could not verify CL-DL proof for Ckey");
    }

    // Compute Q <- [x2] Q1
    Context2pECDSA.ec_group_.scal_mul(public_key_, x2_, Q1);

    // Store CL public key
    pkcl_ = pk;

    // Precompute (Ckey_1^{x_2}, Ckey_2^{x_2})
    QFI ckey1_x2,ckey2_x2;
    Mpz x2{x2_};

#ifdef BICYCL_WITH_PTHREADS
    void (ClassGroup::*nupow_ptr)(QFI &, const QFI &, const Mpz &) const
        = &ClassGroup::nupow;
    std::thread th{nupow_ptr,
                   std::cref(Context2pECDSA.CL_HSMq_.Cl_G()),
                   std::ref(ckey1_x2),
                   std::cref(Ckey.c1()),
                   std::cref(x2)};

    Context2pECDSA.CL_HSMq_.Cl_G().nupow(ckey2_x2, Ckey.c2(), x2);
    th.join();
#else

    Context2pECDSA.CL_HSMq_.Cl_G().nupow(ckey1_x2, Ckey.c1(), x2);
    Context2pECDSA.CL_HSMq_.Cl_G().nupow(ckey2_x2, Ckey.c2(), x2);
#endif

    Ckey_x2_ = CL_HSMqk::CipherText(ckey1_x2, ckey2_x2);
  }

  inline
  void TwoPartyECDSA::Player2::SignPart2(const TwoPartyECDSA & Context2pECDSA,
                                         RandGen & randgen,
                                         const Commitment & commit_R1,
                                         const Mpz & sid)
  {
    // Generate k2 from OpenSSL randomizer
    k2_ = Context2pECDSA.ec_group_.random_mod_order(randgen);

    // Compute R2 <- [k2] P
    Context2pECDSA.ec_group_.scal_mul_gen(R2_, k2_);

    // Store commitment
    commit_ = commit_R1;

    // Compute proof of k2 knowledge
    Mpz sid2;
    Mpz::mulby2(sid2, sid);
    zk_proof_
        = ECNIZKProof(Context2pECDSA.ec_group_, Context2pECDSA.H_, randgen, k2_, R2_, sid2);
  }

  inline
  TwoPartyECDSA::Player2::PresignData TwoPartyECDSA::Player2::SignPart4_offline(
      const TwoPartyECDSA & Context2pECDSA,
      RandGen & randgen,
      const ECPoint & R1,
      const TwoPartyECDSA::CommitmentSecret commit_secret,
      const ECNIZKProof & proof_k1,
      const Mpz & sid)
  {
    // Check commitment of proof matches
    if (false == Context2pECDSA.open(commit_, proof_k1, commit_secret))
    {
      throw ProtocolAbortError(
          "could not verify commited value of ZK-proof (in Sign)");
    }

    // Verify ZK proof
    Mpz sid1;
    Mpz::mulby2(sid1, sid);
    sid1.setbit(0);
    if (false
        == proof_k1.verify(Context2pECDSA.ec_group_, Context2pECDSA.H_, R1, sid1))
    {
      throw ProtocolAbortError("could not verify ZK-proof of k1 knowledge");
    }

    BN r;

    // Compute R <- [k2] R1, and extract r
    ECPoint R(Context2pECDSA.ec_group_);
    Context2pECDSA.ec_group_.scal_mul(R, k2_, R1);
    Context2pECDSA.ec_group_.x_coord_of_point(r, R); // r <- Rx

    // Compute the presignature, a precomputation of C3
    return PresignData(Context2pECDSA, pkcl_, Ckey_x2_, Mpz(r), Mpz(k2_), randgen);
  }

  /* */
  inline
  void TwoPartyECDSA::Player2::SignPart4_online (const TwoPartyECDSA & Context2pECDSA,
                          const HashAlgo::Digest & m,
                          const PresignData & presign)
  {
    const CL_HSMqk & CL = Context2pECDSA.CL_HSMq_;

    // Compute C3,2 = C3,2,p * f^{H(m) * k2^{-1}}
    Mpz exp{m};
    Mpz::mul(exp, exp, presign.k2_inv_); // exp = H(m) * k2^{-1}
    QFI C32;
    CL.Cl_G().nucomp(C32, presign.C32p_, CL.power_of_f(exp));

    C3_ = CLCipherText(presign.C31_, C32);
  }

  inline
  void TwoPartyECDSA::Player2::SignPart4(
      const TwoPartyECDSA & Context2pECDSA,
      RandGen & randgen,
      const HashAlgo::Digest & m,
      const ECPoint & R1,
      const TwoPartyECDSA::CommitmentSecret commit_secret,
      const ECNIZKProof & proof_k1,
      const Mpz & sid)
  {
    PresignData presign{
      SignPart4_offline(Context2pECDSA, randgen, R1, commit_secret, proof_k1, sid)
    };
    SignPart4_online(Context2pECDSA, m, presign);
  }

  //////////////////////////////////////////////////////////////////////////////
  //  _______      _____    ___  _   ___ _______   __  ___ ___ ___  ___   _
  // |_   _\ \    / / _ \  | _ \/_\ | _ \_   _\ \ / / | __/ __|   \/ __| /_\.
  //   | |  \ \/\/ / (_) | |  _/ _ \|   / | |  \ V /  | _| (__| |) \__ \/ _ \.
  //   |_|   \_/\_/ \___/  |_|/_/ \_\_|_\ |_|   |_|   |___\___|___/|___/_/ \_\.
  //
  inline
  TwoPartyECDSA::TwoPartyECDSA(const SecLevel & seclevel, RandGen & randgen)
    : seclevel_{seclevel},
      ec_group_{seclevel_},
      CL_HSMq_{ec_group_.order(),
               1,
               seclevel_,
               randgen,
               CL_Params{seclevel.statistical()}},
      H_{seclevel_}
  {
    // Nothing to do
  }

  /**
   * Getters
   *
   **/
  inline const ECGroup & TwoPartyECDSA::ec_group() const
  {
    return ec_group_;
  }

  inline const CL_HSMqk & TwoPartyECDSA::CL_HSMq() const
  {
    return CL_HSMq_;
  }

  inline
  HashAlgo & TwoPartyECDSA::H() const
  {
    return H_;
  }

  inline
  HashAlgo::Digest TwoPartyECDSA::hash (const std::vector<unsigned char> & m) const
  {
    return H_(m);
  }

  inline std::tuple<TwoPartyECDSA::Commitment, TwoPartyECDSA::CommitmentSecret>
  TwoPartyECDSA::commit(RandGen & randgen, const ECNIZKProof & proof) const
  {
    size_t nbytes = seclevel_.nbits() >> 3; /* = seclevel/8 */
    TwoPartyECDSA::CommitmentSecret r(randgen.random_bytes(nbytes));
    // Commitment <- H(r, R, z)
    // Commitment secret <- r
    return std::make_tuple(
        H_(r, ECPointGroupCRefPair(proof.R(), ec_group_), proof.z()),
        r);
  }

  inline
  bool TwoPartyECDSA::open(const Commitment & c,
                           const ECNIZKProof & proof,
                           const TwoPartyECDSA::CommitmentSecret & r) const
  {
    Commitment c2(
        H_(r, ECPointGroupCRefPair(proof.R(), ec_group_), proof.z()));
    return c == c2;
  }

  inline
  bool TwoPartyECDSA::verify(const ECSignature & signature,
                             const PublicKey & Q,
                             const HashAlgo::Digest & m) const
  {
    return signature.verify(ec_group_, Q, m);
  }

}

#endif /* BICYCL_TWOPARTY_ECDSA_INL */
