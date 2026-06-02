# Mathematical background {#maths}
\tableofcontents

We give here a high level overview of class groups of imaginary
quadratic fields (adapted from Section 2 of \cite{BCIL23}).

## Quadratic fields, orders and class groups

*Imaginary quadratic fields* are extensions of degree \f$2 \f$ of \f$\Q \f$ that
can be written as \f$K=\Q(\sqrt{D}) \f$ where \f$D<0 \f$ is a square free
integer. To such a field is attached an integer, called
*fundamental discriminant* and denoted \f$\DK \f$, that is defined as
\f$\DK := D \f$ if \f$D \equiv 1 \pmod{4} \f$ and \f$\DK:=4D \f$ otherwise.

The ring \f$\OK \f$ of algebraic integers in \f$K \f$, also called the
*maximal order*, can  be written as \f$\Z[\omega_K] \f$ where
\f$\omega_K = \frac{\DK + \sqrt{\DK}}{2} \f$.
One can define special subrings of  \f$\OK \f$, called *orders*, associated to a
non fundamental discriminant \f$\Delta_\ell := \ell^2 \DK \f$ where \f$\ell \f$
is called a *conductor*. The order \f$\O_{\Delta_\ell} \f$ of conductor
\f$\ell \f$ is the ring \f$\Z[\ell \omega_K] \f$, it has index \f$\ell \f$ in
\f$\OK \f$.

To each discriminant \f$\Delta \f$ (fundamental or not), one can associate a
finite abelian group, called the *ideal class group* and denoted \f$\Cl \f$
defined as the quotient of the group of (invertible fractional) ideals of
\f$\O_\Delta \f$ by the subgroup of principal ideals. The order of this
group is called the *class number* and denoted \f$h(\Delta) \f$.

One has \f$h(\Delta) \f$ close to \f$\sqrt{|\Delta|} \f$ in general and one can
compute its number of bits in polynomial time using the analytic class
number formula. However, the full value of \f$h(\Delta) \f$  is only known to be
computable from \f$\Delta \f$ in sub-exponential time \f$L_{1/2}(|\Delta|) \f$.
As a result, these groups have been extensively used in the past decade to
implement cryptographic protocols based on groups of unknown order,  as they can
be generated with a public coin setup: it is sufficient to generate the integer
\f$\Delta \f$ to use these groups. This is in contrast to the group of
invertible elements of \f$\Z/N\Z \f$ for which  one needs a trusted setup to
generate an RSA integer \f$N \f$, in order to keep its factorization secret, and
thus the order of the group unknown.  Another feature used by cryptographic
applications is that discrete logarithms in \f$\Cl \f$ are also hard to compute
(again only sub-exponential time algorithms with complexity
\f$L_{1/2}(|\Delta|) \f$ are known).

## Elements and group law

Elements of \f$\Cl \f$ can be represented in a compact form. One can define a
system of representatives of the classes with the notion of reduced ideals.
Ideals are of the form \f$a\Z + \frac{-b+ \sqrt{\Delta}}2\Z \f$,  where
\f$a,b \in \N \f$ and \f$a \f$ and \f$b \f$ are smaller than \f$\sqrt{|\Delta|}
\f$ when the ideal is reduced. As a result, one needs \f$\log_2(|\Delta|) \f$
bits to represent an element of the class group. Combined with the fact that the
best known attacks against cryptographic problems in class groups are of
complexity \f$L_{1/2}(|\Delta|) \f$ instead of \f$L_{1/3}(N) \f$ for factoring
based schemes, this leads to bandwidth improvement for cryptographic
applications.

The group law corresponds to product of ideals followed by a reduction operation
to find the unique reduced ideal of the class. In practice, the group law is
computed using the language of positive definite binary quadratic forms. Let
\f$a,b,c \f$ be three relatively prime integers such that \f$a>0 \f$ and
\f$\Delta = b^2-4ac \f$, we will denote \f$f:=(a,b,c) \f$ the primitive positive
definite binary quadratic form over the integers, \f$f(X,Y)=aX^2+bXY+cY^2 \f$ of
discriminant \f$\Delta \f$. One can define an equivalence relation on forms from
the action of \f$SL_2(\Z) \f$. The class group  \f$\Cl \f$ is actually
isomorphic to the set of forms modulo this equivalence relation. Moreover there
is an explicit correspondence between ideals and forms: the class of
the form \f$(a,b,c) \f$ corresponds to the ideal
\f$a\Z + \frac{-b+\sqrt{\Delta}}2 \Z \f$. The definition of the unique
representative of the class is more natural when working with forms: it is the
reduced form \f$(a,b,c) \f$, which satisfies \f$-a < b \leqslant a \f$,
\f$a\leqslant c \f$ and if \f$a=c \f$ then \f$b\geqslant 0 \f$.

The group law is implemented using Gauss' composition of forms and a
reduction algorithm for forms devised by Lagrange. More efficient
algorithms have been proposed by Shanks to compute the group law,
NUCOMP and NUDUPL, where a partial reduction is applied during
composition. The BICYCL library represents elements of the class group
\f$\Cl \f$ as triplets of integers corresponding to reduced binary quadratic
forms and implements Shank's algorithms.

## Maps between class groups

We have seen that from a fundamental (square free) discriminant \f$\DK \f$, one
can define a class group \f$\ClDeltaK \f$ associated with the ring of integers
\f$\OK \f$. Moreover, from \f$\DK \f$ one can define a non fundamental
discriminant \f$\Delta_\ell := \ell^2 \DK \f$ and a class group
\f$\Cl(\Delta_\ell) \f$ associated with the suborder
\f$\O_{\Delta_\ell} \subset \OK \f$. This inclusion of the orders actually
translates into a relation on the class groups \f$\Cl(\Delta_\ell) \f$ and
\f$\ClDeltaK \f$.
First one defines a map on the level of the ideals. A nonzero ideal \f$I \f$ of
\f$\O_{\Delta_\ell} \f$ is said to be prime to \f$\ell \f$ if
\f$I + \ell \O_{\Delta_\ell} = \O_{\Delta_\ell} \f$. Then the map
\f$I \mapsto I\OK \f$ is an isomorphism from the group of ideals of
\f$\O_{\Delta_\ell} \f$ prime to \f$\ell \f$ to the group of ideals of
\f$\OK \f$ prime to \f$\ell \f$. This map and the inverse map are explicit and
can be computed efficiently knowing the conductor \f$\ell \f$. By passing to
the quotient, we obtain a surjection
\f$\varphi_\ell: \Cl(\Delta_\ell) \twoheadrightarrow \ClDeltaK \f$.
Studying the kernel of this map, one obtains,  for \f$\DK < -4 \f$, the formula
\f[
   h(\O_{\Delta_\ell}) = h(\OK) \cdot \ell \cdot
           \prod_{p | \ell}\left(1 - \legendre{\DK}{p} \frac{1}{p} \right).
\f]

The instantiation of the CL framework to design linearly homomorphic
encryption schemes in class groups heavily relies on this formula and on the
fact that the discrete logarithm problem can be easy in \f$\ker \varphi_\ell \f$
for appropriate choices of \f$\DK \f$ and \f$\ell \f$.

## Squares and square roots

A last important property of class groups for cryptography concerns
squares and square root computations. Knowing the factorization of the
discriminant \f$\Delta \f$, it is possible to determine in polynomial time
if an element of \f$\Cl \f$ is a square and compute its square roots. The
situation is somewhat similar to \f$\Z/N\Z \f$ for an RSA integer \f$N=pq \f$
where one can compute the values of the Legendre symbol relative to \f$p \f$ and
\f$q \f$ to determine if an element is a square. For class groups, genus theory
defines various characters that play the role of these symbols, depending on the
specific form of the discriminant. Genus theory is of crucial importance in the
instantiation of the CL framework modulo \f$2^k \f$ (see Subsection 2.3 of
\cite{CLT22} for more details).
