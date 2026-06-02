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

/**
 * @example TwoPartyECDSA_example.cpp
 * This file is an example of how to use the BICYCL::TwoPartyECDSA class.\n
 * It shows how to setup the two-party signing system, how to sign  message,
 * and how to verify the signature.
 *
 * @defgroup ECDSA_TWOPARTY 2-Party ECDSA
 * @ingroup ECDSA
 * 2-party ECDSA using class groups.
 *
 */

#ifndef BICYCL_EC_TWOPARTY_ECDSA_HPP
#define BICYCL_EC_TWOPARTY_ECDSA_HPP

#include <iostream>
#include <vector>

#include "bicycl/arith/gmp_extras.hpp"
#include "bicycl/arith/openssl_wrapper.hpp"
#include "bicycl/cl/CL_DL_proof.hpp"
#include "bicycl/cl/CL_HSMqk.hpp"
#include "bicycl/ec/proofs.hpp"
#include "bicycl/ec/signature.hpp"

namespace BICYCL
{
/*****************************************************************************
 * @brief Implmentation of the TwoPartyECDSA protocol defined in IACR 2019/503 (https://eprint.iacr.org/2019/503).
 * @ingroup ECDSA_TWOPARTY
 * @nosubgrouping
 ****************************************************************************/
class TwoPartyECDSA
{
  public:
    using PublicKey = ECPoint;
    using Commitment = HashAlgo::Digest;
    using CommitmentSecret = std::vector<unsigned char>;
    using CLPublicKey = CL_HSMqk::PublicKey;
    using CLSecretKey = CL_HSMqk::SecretKey;
    using CLCipherText = CL_HSMqk::CipherText;

    /*************************************************************************
     * @brief Indicates the protocol cannot proceed and must be aborted.
     * @details This exception usually means that at least one player was dishonest in
     * the protocol execution.
     ************************************************************************/
    class ProtocolAbortError : public std::runtime_error
    {
      public:
        using runtime_error::runtime_error;
    };

    /*************************************************************************
       * @brief Implementation of "P1" and its actions in the TwoPartyECDSA protocol.
       * @nosubgrouping
       ************************************************************************/
    class Player1
    {
      public:
        using PresignData = std::array<BN, 2>;

        /******************************************************
           * @name Constructors
           *@{
           *****************************************************/
        /**
           * @brief Construct a Player 1
           *
           * @param[in] Context_2pECDSA The public parameters for the protocol.
           */
        explicit Player1(const TwoPartyECDSA & Context_2pECDSA);
        /**@}*/

        /******************************************************
           * @name Getters for Keygen
           * Methods to retrieve values for the keygen phase.
           *@{
           *****************************************************/
        /**
           * @brief Get \f$Q1=x1*P\f$
           */
        const ECPoint & Q1 () const;

        /**
           * @brief Get the ciphertext of x1 \f$Ckey=Enc(pk,x1)\f$
           */
        const CL_HSMqk::CipherText & Ckey () const;

        /**
           * @brief Get the public key for CL encryption \f$pk\f$
           */
        const CLPublicKey & pkcl () const;

        /**
           * @brief Get the public key \f$Q=x1*x2*P\f$
           */
        const PublicKey & public_key () const;

        /**
           * @brief Get the proof of knowledge of the CL discrete log \f$x1\f$
           * in \f$Ckey=Enc(pk,x1)\f$.
           */
        const CLDLZKProof & proof_ckey () const;

        /******************************************************
           * @name Getters for Sign
           * Methods to retrieve values for the sign phase
           *@{
           *****************************************************/

        /**
           * @brief Get \f$R1=k1*P\f$
           */
        const ECPoint & R1 () const;
        /**@}*/

        /******************************************************
           * @name Getters for Keygen and Sign
           * Methods to retrieve values used both in the keygen and sign phases
           *@{
           *****************************************************/

        /**
           * @brief Get the commitment to the proof
           */
        const Commitment & commit () const;

        /**
           * @brief Get the commitment secret
           */
        const CommitmentSecret & commit_secret () const;

        /**
           * @brief Get the proof of knowledge of the elliptic curve discrete log.\n
           * During the Keygen phase, it proves knowledge of \f$x1\f$ in \f$Q1=x1*P\f$.\n
           * During the Sign phase, it proves knowledge of \f$k1\f$ in \f$R1=k1*P\f$.\n
           */
        const ECNIZKProof & zk_com_proof () const;
        /**@}*/

        /******************************************************
           * @name Keygen computation
           * Methods to perform computation of the keygen steps.
           *@{
           *****************************************************/

        /**
           * @brief Keygen Part 1
           * @details
           * Select x1
           * Compute Q1 <- [x1] P
           * Output commitment to Q1
           **/
        void KeygenPart1 (const TwoPartyECDSA & Context2pECDSA,
                          RandGen & randgen);

        /**
           * @brief Keygen Part 3
           * @details
           * Get Q2 and store Q <- [x1] Q2
           * Output:
           *   - Ckey <- CL(x1) + CL public key
           *   - Zero knowledge proof of x1 knowledge
           *
           **/
        void KeygenPart3 (const TwoPartyECDSA & Context2pECDSA,
                          RandGen & randgen,
                          const ECPoint & Q2,
                          const ECNIZKProof & proof_x2);
        /**@}*/

        /******************************************************
           * @name Sign computation
           * Methods to perform computation of the sign steps.
           *@{
           *****************************************************/

        /**
           *  @brief Sign part 1
           *  Select k1
           *  Store R1 <- [k1] P
           *  Output commitment to R1
           **/
        void SignPart1 (const TwoPartyECDSA & Context2pECDSA,
                        RandGen & randgen,
                        const Mpz & sid);

        /**
           * @brief Sign part 3
           * @details
           * Get R2, compute and store r <- Rx, from R <- [k1] R2
           * Output zero knowledge proof of k1 knowledge
           **/
        PresignData SignPart3 (const TwoPartyECDSA & Context2pECDSA,
                               const ECPoint & R2,
                               const ECNIZKProof & proof_k2,
                               const Mpz & sid);

        /**
           * @brief Sign part 5
           * @details
           * Get C3
           * Compute and Output Signature
           **/
        ECSignature SignPart5 (const TwoPartyECDSA & Context2pECDSA,
                             const HashAlgo::Digest & m,
                             const CL_HSMqk::CipherText & C3);

        /**
           * @brief Sign part 5 TODO
           * @details
           * Get C3
           * Compute and Output Signature
           **/
        ECSignature SignPart5 (const TwoPartyECDSA & Context2pECDSA,
                             const HashAlgo::Digest & m,
                             const CL_HSMqk::CipherText & C3,
                             const PresignData & presign_data);
        /**@}*/

      private:
        // Mpz sid_;
        BN x1_;                 /**  x1 random from Z/qZ */
        BN k1_;                 /**  k1 random from Z/qZ */
        BN r_;                  /**  r = Rx, from R = [k1] R2 */
        ECPoint Q1_;            /**  Q1 = [x1] P */
        ECPoint R1_;            /**  R1 = [k1] P */
        PublicKey public_key_;           /**  Q = [x1] Q2 */
        Commitment commit_;              /**  Commitment (to Q1, R1) */
        CommitmentSecret commit_secret_; /**  Secret used in commitment value */
        CLSecretKey skcl_;    /**  Secret key for CL_HSMqk decryption */
        CLPublicKey pkcl_;    /**  Public key for CL encryption */
        CLCipherText Ckey_; /**  Encrypted x1 */
        CLDLZKProof proof_ckey_;    /**  CL-DL proof for x1 */
        ECNIZKProof zk_com_proof_;  /**  Proof of knowledge (for x1, k1) */
    }; /* Player1 */


    /*************************************************************************
       * @brief Implementation of "P2" and its actions in the TwoPartyECDSA protocol.
       * @nosubgrouping
       ************************************************************************/
    class Player2
    {
      public:
        /*************************************************************************
          * @brief TODO
          * @nosubgrouping
          *************************************************************************/
        class PresignData
        {
          public:
            /**
            * @brief TODO
            *
            * @param[in/out] Context2pECDSA
            * @param[in/out] pk
            * @param[in/out] ckey1_x2
            * @param[in/out] ckey2_x2
            * @param[in/out] k2
            * @param[in/out] t
            *
            */
            PresignData(const TwoPartyECDSA & Context2pECDSA,
                        const CLPublicKey pkcl,
                        const CLCipherText & ckey_x2,
                        const Mpz & r,
                        const Mpz k2,
                        const Mpz t);

            /**
              * @brief TODO
              *
              * @param[in/out] Context2pECDSA
              * @param[in/out] pk
              * @param[in/out] ckey1_x2
              * @param[in/out] ckey2_x2
              * @param[in/out] randgen
              *
              */
            PresignData(const TwoPartyECDSA & Context2pECDSA,
                        const CLPublicKey pkcl,
                        const CLCipherText & ckey_x2,
                        const Mpz & r,
                        const Mpz k2,
                        RandGen & randgen);

            Mpz k2_inv_;
            QFI C31_;
            QFI C32p_;
        };

        /******************************************************
         * @name Constructors
         *@{
         *****************************************************/

        /**
           * @brief Construct a Player 2
           *
           * @param[in] Context_2pECDSA The public parameters for the protocol.
           */
        explicit Player2(const TwoPartyECDSA & Context2pECDSA_);
        /**@}*/

        /******************************************************
           * @name Getters for Keygen
           * Methods to retrieve values for the keygen phase.
           *@{
           *****************************************************/

        /**
           * @brief Get \f$Q2=x2*P\f$
           */
        const ECPoint & Q2 () const;

        /**
           * @brief Get the public key \f$Q=x1*x2*P\f$
           */
        const PublicKey & public_key () const;
        /**
           * @brief Get the public key for CL encryption \f$pk\f$
           */
        const CLPublicKey & pkcl () const;

        /******************************************************
           * @name Getters for Sign
           * Methods to retrieve values for the sign phase
           *@{
           *****************************************************/

        /**
           * @brief Get \f$R2=k2*P\f$
           */
        const ECPoint & R2 () const;

        /**
           * @brief Get \f$C3\f$ the ciphertext of the partial signature.
           * \f$C3=EvalSum(pk,c1,c2)\f$
           */
        const CL_HSMqk::CipherText & C3 () const;

        /******************************************************
           * @name Getters for Keygen and Sign
           * Methods to retrieve values used both in the keygen and sign phases
           *@{
           *****************************************************/

        /**
           * @brief Get the proof of knowledge of the elliptic curve discrete log.\n
           * During the Keygen phase, it proves knowledge of \f$x2\f$ in \f$Q2=x2*P\f$.\n
           * During the Sign phase, it proves knowledge of \f$k2\f$ in \f$R2=k2*P\f$.\n
           */
        const ECNIZKProof & zk_proof () const;
        /**@}*/

        /******************************************************
           * @name Keygen computation
           * Methods to perform computation of the keygen steps.
           *@{
           *****************************************************/

        /**
           * @brief Keygen Part 2
           * @details
           *  Get and store Q1 commitment from P1
           *  Select x2
           *  Output Q2 <- [x1] P
           **/
        void KeygenPart2 (const TwoPartyECDSA & Context2pECDSA,
                          RandGen & randgen,
                          const Commitment & commit_Q1);

        /**
           * @brief Keygen Part 4
           * @details
           * Get Q1, check it matches commitment
           * Get and check proof of x1 knowledge
           * Store pk, Ckey, and Q <- [x2] Q1
           *
           **/
        void KeygenPart4 (const TwoPartyECDSA & Context2pECDSA,
                          const ECPoint & Q1,
                          const CL_HSMqk::CipherText & Ckey,
                          const CLPublicKey & pk,
                          const CommitmentSecret commit_secret,
                          const ECNIZKProof & proof_x1,
                          const CLDLZKProof & proof_ckey);
        /**@}*/

        /******************************************************
           * @name Sign computation
           * Methods to perform computation of the sign steps.
           *@{
           *****************************************************/

        /**
           * @brief Sign part 2
           * @details
           * Get and store R1 commitment from P1
           * Select k2
           * Output R2 <- [k2] P
           * Output zk_proof <- ECNIZKProof(k2, R2)
           **/
        void SignPart2 (const TwoPartyECDSA & Context2pECDSA,
                        RandGen & randgen,
                        const Commitment & commit_R1,
                        const Mpz & sid);


        /**
           * @brief Sign part 4 offline TODO
           * @details
           *
           **/
        PresignData SignPart4_offline (const TwoPartyECDSA & Context2pECDSA,
                                       RandGen & randgen,
                                       const ECPoint & R1,
                                       const CommitmentSecret commit_secret,
                                       const ECNIZKProof & proof_k1,
                                       const Mpz & sid);

        /**
           * @brief Sign part 4 using presignature TODO
           * @details
           * Get m, R1, and compute and Output C3 using presignature
           **/
        void SignPart4_online (const TwoPartyECDSA & Context2pECDSA,
                               const HashAlgo::Digest & m,
                               const PresignData & presign);

        /**
           * @brief Sign part 4
           * @details
           * Get m, R1, and compute and Output C3
           **/
        void SignPart4 (const TwoPartyECDSA & Context2pECDSA,
                        RandGen & randgen,
                        const HashAlgo::Digest & m,
                        const ECPoint & R1,
                        const CommitmentSecret commit_secret,
                        const ECNIZKProof & proof_k1,
                        const Mpz & sid);


        /**@}*/

      private:
        // Mpz sid_;
        BN x2_;               /**  x2 random from Z/qZ */
        BN k2_;               /**  k2 random from Z/qZ */
        ECPoint Q2_;          /**  Q2 = [x2] P */
        ECPoint R2_;          /**  R2 = [k2] P */
        PublicKey public_key_;         /**  Q = [x2] Q1] */
        CLPublicKey pkcl_;     /**  Public key for CL_HSM encryption */
        CL_HSMqk::CipherText Ckey_x2_; /**  Precomputation Ckey^x2 */
        CL_HSMqk::CipherText C3_;      /**  C3 = Enc(k2^-1 *(H(m)+ r*x1*x2)) */
        ECNIZKProof zk_proof_;         /**  Proof of knowledge (for x2, k2) */
        Commitment commit_;            /**  Commitment from P1 */
    }; /* Player2 */

    /******************************************************
       * @name Constructors
       *@{
       *****************************************************/

    /**
       * @brief Construct a TwoPartyECDSA context.
       * @details The constructed object contains the public parameters of the 2-Party ECDSA protocol.\n

       *
       * @param[in] seclevel Security parameter
       * @param[in] randgen Randomness generator
       */
    TwoPartyECDSA(const SecLevel & seclevel, RandGen & randgen);
    /**@}*/


    /******************************************************
       * @name Getters
       * Methods to retrieve the public parameters
       *@{
       *****************************************************/

    /**
       * @brief Get the elliptic curve.
       */
    const ECGroup & ec_group () const;

    /**
       * @brief Get the CL cryptosystem.
       */
    const CL_HSMqk & CL_HSMq () const;

    /**
       * @brief Get the Hash function.
       */
    HashAlgo & H () const;
    /**@}*/

    /******************************************************
     * @name Verify
     * Method for signature verification
     *@{
     *****************************************************/

    /**
      * @brief
      *
      * @param[in] s The signature to verify.
      * @param[in] Q The public key of the TwoPartyECDSA protocol
      * @param[in] m The hashed message to authentify.
      *
      * @return true if signature was successfully verified.
      * @return false otherwise.
      */
    bool
    verify (const ECSignature & s, const PublicKey & Q, const HashAlgo::Digest & m) const;
    /**@}*/

    /**
      * @brief Compute the hash of a vector of bytes
      *
      * @param[in] m The data to hash
      *
      * @return Hash digest (vecotr of bytes)
      */
    HashAlgo::Digest hash (const std::vector<unsigned char> & m) const;

  protected:
    /**
       * @brief Compute commitment of an ECNIZKProof, for KeygenPart1 and SignPart1.
       *
       * @param[in] proof The proof to commit to.
       *
       * @return std::tuple made of (Commitment, CommitmentSecret)
       */
    std::tuple<Commitment, CommitmentSecret>
    commit (RandGen & randgen, const ECNIZKProof & proof) const;

    /**
       * @brief Open commitment to an ECNIZKProof, for KeygenPart4 and SignPart4.
       *
       * @param[in] c Commitment to verify.
       * @param[in] proof Proof commited to.
       * @param[in] r The commitment secret.
       *
       * @return true if commitment was successfully verified. false otherwise.
       */
    bool open (const Commitment & c,
               const ECNIZKProof & proof,
               const CommitmentSecret & r) const;


  private:

    const SecLevel seclevel_;         /** Security parameter */
    const ECGroup ec_group_; /** Elliptc curve      */
    const CL_HSMqk CL_HSMq_;          /** CL cryptoystem     */
    mutable HashAlgo H_;     /** Hash function      */
};

} /* BICYCL namespace */

#include "twoParty_ECDSA.inl" // IWYU pragma: keep

#endif                        /* BICYCL_EC_TWOPARTY_ECDSA_HPP */
