/*
 * BICYCL Implements CryptographY in CLass groups
 * Copyright (C) 2025  Cyril Bouvier <cyril.bouvier@lirmm.fr>
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
#include <cassert>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "bicycl.hpp"

#define MAXPACKETSIZE 512

/* Global vars */
extern int udp_socket_fd;

////////////////////////////////////////////////////////////////////////////////
//    ___ ___ _  _ ___
//   / __| __| \| |   \`
//   \__ \ _|| .` | |) |
//   |___/___|_|\_|___/
//
////////////////////////////////////////////////////////////////////////////////
/**
 * @brief Send an BN. Blocking until response.
 */
inline void send (const sockaddr_in & P_addr, const BICYCL::BN & a)
{
  auto vec = static_cast<std::vector<uint8_t>>(a);
  ssize_t ret = sendto(udp_socket_fd,
                       vec.data(),
                       vec.size(),
                       MSG_CONFIRM,
                       (const struct sockaddr *)&P_addr,
                       sizeof(P_addr));
  if (ret == -1)
  {
    perror("Failed to send BN");
    std::cout << "  Value: " << a << '\n';
    std::cout << "  Size: " << vec.size() << " bytes" << std::endl;
  }
}

/**
 * @brief Send an ECPoint (two BN). Blocking until response.
 * Two transmissions.
 */
inline void send (const sockaddr_in & P_addr,
                  const BICYCL::ECGroup & E,
                  const BICYCL::ECPoint & P)
{
  BICYCL::BN x, y;
  E.coords_of_point(x, y, P);
  send(P_addr, x);
  send(P_addr, y);
}

/**
 * @brief Send an ECNIZKProof (one ECpoint and 1 BN). Blocking until response.
 * Three transmissions.
 */
inline void send (const sockaddr_in & P_addr,
                  const BICYCL::ECGroup & E,
                  const BICYCL::ECNIZKProof & proof)
{
  send(P_addr, E, proof.R());
  send(P_addr, proof.z());
}

/**
 * @brief Send a Mpz. Blocking.
 */
inline void send (const sockaddr_in & P_addr, const BICYCL::Mpz & d)
{
  // uint8_t buffer[MAXPACKETSIZE];
  // size_t len;
  // mpz_export(buffer, &len, 1, 1, 0, 0, static_cast<mpz_srcptr>(d));
  std::vector<uint8_t> vec = static_cast<std::vector<uint8_t>>(d);
  assert(vec.size() <= MAXPACKETSIZE - 1u);

  // Data MSB stores the sign (-1, 0, or 1)
  vec.push_back(d.sgn());

  ssize_t ret = sendto(udp_socket_fd,
                       vec.data(),
                       vec.size(),
                       MSG_CONFIRM,
                       (const struct sockaddr *)&P_addr,
                       sizeof(P_addr));
  if (ret == -1) perror("Failed to send Mpz");
}

/**
 * @brief Send a QFI (3 MPZs). Blocking.
 * @param[in] compress If true, send the compressed representation instead
 */
inline void
send (const sockaddr_in & P_addr, const BICYCL::QFI & f, bool compress = false)
{
  if (compress)
  {
    BICYCL::QFICompressedRepresentation fzip = f.compressed_repr();
    // Send ap, g, tp and b0
    send(P_addr, fzip.ap);
    send(P_addr, fzip.g);
    send(P_addr, fzip.tp);
    send(P_addr, fzip.b0);
    // Send sign info
    uint8_t neg = fzip.is_neg;
    ssize_t ret = sendto(udp_socket_fd,
                         &neg,
                         1u,
                         MSG_CONFIRM,
                         (const struct sockaddr *)&P_addr,
                         sizeof(P_addr));
    if (ret == -1) perror("Failed to send QFI compressed");
  }
  else
  {
    send(P_addr, f.a());
    send(P_addr, f.b());
    send(P_addr, f.c());
  }
}

/**
 * @brief Send a CL Ciphertext (2 QFIs). Blocking.
 * @param[in] compress If true, send the compressed representation instead
 */
inline void send (const sockaddr_in & P_addr,
                  const BICYCL::CL_HSMqk::CipherText & ct,
                  bool compress = false)
{
  send(P_addr, ct.c1(), compress);
  send(P_addr, ct.c2(), compress);
}

/**
 * @brief Send a CLDL proof (1 ECPoint and 3 MPZs). Blocking.
 */
inline void send (const sockaddr_in & P_addr,
                  const BICYCL::ECGroup & E,
                  const BICYCL::CLDLZKProof & proof)
{
  send(P_addr, E, proof.R());
  send(P_addr, proof.u1());
  send(P_addr, proof.u2());
  send(P_addr, proof.chl());
}

/**
 * @brief Send an array of bytes. Blocking until response.
 */
inline void
send (const sockaddr_in & P_addr, const uint8_t * buffer, size_t len)
{
  ssize_t ret = sendto(udp_socket_fd,
                       buffer,
                       len,
                       MSG_CONFIRM,
                       (const struct sockaddr *)&P_addr,
                       sizeof(P_addr));
  if (ret == -1) perror("Failed to send buffer");
}

/**
 * @brief Send a vector of bytes. Blocking until response.
 */
inline void send (const sockaddr_in & P_addr, const std::vector<uint8_t> & vec)
{
  send(P_addr, vec.data(), vec.size());
}

//////////////////////////////////////////////////////////////////////////////
//    ___ ___ ___ ___ _____   _____
//   | _ \ __/ __| __|_ _\ \ / / __|
//   |   / _| (__| _| | | \ V /| _|
//   |_|_\___\___|___|___| \_/ |___|
//
//////////////////////////////////////////////////////////////////////////////

/**
 * @brief Receive a BN. Blocking until reception.
 */
inline BICYCL::BN receive_bn (const sockaddr_in & P_addr)
{
  uint8_t buffer[MAXPACKETSIZE];
  socklen_t socket_len = sizeof(P_addr);
  ssize_t n = recvfrom(udp_socket_fd,
                       buffer,
                       MAXPACKETSIZE,
                       MSG_WAITALL,
                       (struct sockaddr *)&P_addr,
                       &socket_len);

  if (n == -1) perror("Failed to receive BN");

  std::vector<uint8_t> vec(buffer, buffer + n);
  return BICYCL::BN(vec);
}

/**
 * @brief Receive a ECPoint (two BN). Blocking until reception.
 */
inline BICYCL::ECPoint
receive_ECPoint (const sockaddr_in & P_addr, const BICYCL::ECGroup & E)
{
  // Receive x coord
  BICYCL::BN x = receive_bn(P_addr);
  // Receive y coord
  BICYCL::BN y = receive_bn(P_addr);

  return BICYCL::ECPoint(E, x, y);
}

/**
 * @brief Receive an ECNIZKProof (one ECpoint and 1 BN).
 * Blocking until reception.
 */
inline BICYCL::ECNIZKProof
receive_ECNIZKproof (const sockaddr_in & P_addr,
                     const BICYCL::ECGroup & E)
{
  // Receive R
  BICYCL::ECPoint R = receive_ECPoint(P_addr, E);
  // Receive z
  BICYCL::BN z = receive_bn(P_addr);

  return BICYCL::ECNIZKProof(E, R, z);
}

/**
 * @brief Receive a Mpz. Blocking until reception.
 */
inline BICYCL::Mpz receive_mpz (const sockaddr_in & P_addr)
{
  uint8_t buffer[MAXPACKETSIZE];
  socklen_t socket_len = sizeof(P_addr);
  ssize_t n = recvfrom(udp_socket_fd,
                       buffer,
                       MAXPACKETSIZE,
                       MSG_WAITALL,
                       (struct sockaddr *)&P_addr,
                       &socket_len);
  if (n == -1) perror("Failed to receive Mpz");

  // n-1 first bytes are the absolute value
  std::vector<uint8_t> vec(buffer, buffer + n - 1);
  BICYCL::Mpz d(vec);

  // MSB gives the sign
  if ((int8_t)buffer[n - 1] == -1) d.neg();

  return d;
}

/**
 * @brief Receive a QFI (3 MPZs). Blocking until reception.
 *
 * @param[in] compress If true, receive the QFI in compressed representation
 * @param[in] disc     Class group discriminant to compute the QFI coefficients.
                       Only used if compress is  set to true, otherwise ignored.
 */
inline BICYCL::QFI receive_qfi (const sockaddr_in & P_addr,
                                bool compressed = false,
                                const BICYCL::Mpz & disc = BICYCL::Mpz(0UL))
{
  if (compressed)
  {
    if (disc >= 0UL)
      throw std::invalid_argument("receive_qfi: please provide a discriminant "
                                  "for the compressed QFI representation");
    BICYCL::Mpz ap, g, tp, b0;
    // Receive ap, g, tp and b0
    ap = receive_mpz(P_addr);
    g = receive_mpz(P_addr);
    tp = receive_mpz(P_addr);
    b0 = receive_mpz(P_addr);
    // Receive sign info
    uint8_t neg;
    socklen_t socket_len = sizeof(P_addr);
    ssize_t n = recvfrom(udp_socket_fd,
                         &neg,
                         1u,
                         MSG_WAITALL,
                         (struct sockaddr *)&P_addr,
                         &socket_len);
    if (n == -1) perror("Failed to receive QFI compressed");

    BICYCL::QFICompressedRepresentation f(ap, g, tp, b0, neg);
    return BICYCL::QFI(f, disc);
  }
  else {
    BICYCL::Mpz a, b, c;
    a = receive_mpz(P_addr);
    b = receive_mpz(P_addr);
    c = receive_mpz(P_addr);
    return BICYCL::QFI(a, b, c);
  }
}

/**
 * @brief Receive a CL Ciphertext (2 QFIs). Blocking until reception.
 *
 * @param[in] compress If true, receive the QFI in compressed representation
 * @param[in] disc     Class group discriminant to compute the QFI coefficients.
                       Only used if compress is  set to true, otherwise ignored.
 */
inline BICYCL::CL_HSMqk::CipherText
receive_CLcipher (const sockaddr_in & P_addr,
                  bool compressed = false,
                  const BICYCL::Mpz & disc = BICYCL::Mpz(0UL))
{
  BICYCL::QFI c1 = receive_qfi(P_addr, compressed, disc);
  BICYCL::QFI c2 = receive_qfi(P_addr, compressed, disc);
  return BICYCL::CL_HSMqk::CipherText(c1, c2);
}

/**
 * @brief Receive a CLDL proof (1 ECPoint and 3 MPZs). Blocking until reception.
 */
inline BICYCL::CLDLZKProof
receive_CLDLproof (const sockaddr_in & P_addr,
                   const BICYCL::ECGroup & E)
{
  // Receive R
  BICYCL::ECPoint R = receive_ECPoint(P_addr, E);
  // Receive u1, u2, ch
  BICYCL::Mpz u1 = receive_mpz(P_addr);
  BICYCL::Mpz u2 = receive_mpz(P_addr);
  BICYCL::Mpz chl = receive_mpz(P_addr);

  return BICYCL::CLDLZKProof(E, R, u1, u2, chl);
}

/**
 * @brief Receive an array of bytes. Blocking until reception.
 */
inline std::vector<uint8_t> receive_bytes (const sockaddr_in & P_addr)
{
  uint8_t buffer[MAXPACKETSIZE];
  socklen_t socket_len = sizeof(P_addr);
  ssize_t n = recvfrom(udp_socket_fd,
                       buffer,
                       MAXPACKETSIZE,
                       MSG_WAITALL,
                       (struct sockaddr *)&P_addr,
                       &socket_len);

  if (n == -1) perror("Failed to receive Mpz");

  return std::vector<uint8_t>(buffer, buffer + n);
}