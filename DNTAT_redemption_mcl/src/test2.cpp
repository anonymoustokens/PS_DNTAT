
#include <mcl/bn256.hpp>
// #include <mcl/impl/bn_c_impl.hpp>
#include <mcl/lagrange.hpp>
#include <iostream>
#include <array>
#include <vector>
#include <string>
#include <chrono>
#include <iomanip>

using namespace mcl::bn256;
using namespace std::chrono;



struct PublicKey {
    std::array<G1, 4> g1_keys;
    std::array<G2, 4> g2_keys;
};

struct SecretKey {
    std::array<Fr, 4> fr_keys;
};

void Hash(G1& P, const std::string& m)
{
    Fp t;
    t.setHashOf(m);
    mapToG1(P, t);
}


void Hash(G2& P, const std::string& m)
{
    Fp hash_in;
    hash_in.setHashOf(m);
    Fp2 hash;

    hash.set(hash_in, hash_in);

    mapToG2(P, hash);
}


std::pair<PublicKey, SecretKey> generateKeyPair(
    const G1& P, const G2& Q
) {
    PublicKey pk;
    SecretKey sk;



    for (auto& val : sk.fr_keys) {
        val.setByCSPRNG();
    }


    for (size_t j = 0; j < sk.fr_keys.size(); ++j) {
        G1::mul(pk.g1_keys[j], P, sk.fr_keys[j]);
    }


    for (size_t j = 0; j < sk.fr_keys.size(); ++j) {
        G2::mul(pk.g2_keys[j], Q, sk.fr_keys[j]);
    }

    return std::pair<PublicKey, SecretKey>(pk, sk);
}

std::pair<G1, Fr> U_keygen(
    const G1& P
) {
    Fr sku;
    G1 pku;


    sku.setByCSPRNG();

    G1::mul(pku, P, sku);

    return std::make_pair(pku, sku);
}


G1 sign(
    const G1& h_prime,
    const std::array<Fr, 4>& y,
    const Fr& x,
    const Fr& omega
) {
    //  theta = Hash(h')
    // std::vector<unsigned char> h_data;
    unsigned char h_data[64];
    h_prime.serialize(h_data, 64);
    Fr theta;
    theta.setHashOf(h_data, 64);

    //  sigma_i = h'*y1 + theta*G1*y2 + x*G1*y3 + omega*G1*y4
    G1 sigma;

    //  h'*y1
    G1 term1;
    G1::mul(term1, h_prime, y[0]);

    //  theta*y2
    G1 term2;
    G1::mul(term2, h_prime, theta);
    G1::mul(term2, term2, y[1]);

    //  x*y3
    G1 term3;
    G1::mul(term3, h_prime, x);
    G1::mul(term3, term3, y[2]);

    //  omega*y4
    G1 term4;
    G1::mul(term4, h_prime, omega);
    G1::mul(term4, term4, y[3]);

    sigma = term1;
    sigma += term2;
    sigma += term3;
    sigma += term4;

    return  sigma;
}

std::pair<G2, Fr> prove1(
    const std::array<G2, 4>& Y_bar,
    const Fr& x,
    const Fr& omega ,
    Fr alpha,
    Fr beta
) {
  //  sigma_i = h'*y1 + theta*G1*y2 + x*G1*y3 + omega*G1*y4
    G2 sigma_bar;
    G2 R;
    Fr comm;

    G2 term1;
    G2::mul(term1, Y_bar[2], x);


    G2 term2;
    G2::mul(term2, Y_bar[3], omega);


    sigma_bar = term1;
    sigma_bar += term2;


    G2 term3;
    G2::mul(term1, Y_bar[2], alpha);


    G2 term4;
    G2::mul(term2, Y_bar[3], beta);
    R = term1;
    R += term2;


    // std::vector<unsigned char> R_data;
    unsigned char R_data[96];
    R.serialize(R_data, 96);
    // Fr comm;
    comm.setHashOf(R_data, 96);
    return std::make_pair(sigma_bar, comm);
}



Fr verify1(
    const std::array<G2, 4>& Y_bar,
    const G1& sigma,
    const G1& h_prime,
    const G2& sigma_bar,
    const G2& Q
) {
    // std::vector<unsigned char> h_data;
    unsigned char h_data[64];
    h_prime.serialize(h_data, 64);

    Fr theta;
    theta.setHashOf(h_data, 64);


    G2 tmp;

    G2 term1;
    G2::mul(term1, Y_bar[1], theta);

    tmp = sigma_bar;
    tmp += term1;
    tmp += Y_bar[0];


    GT e1;
    GT e2;
    pairing(e1, h_prime, tmp);
    pairing(e2, sigma, Q);

    Fr ch;
    if (e1 == e2) {
         ch.setByCSPRNG();
    } else {
         ch.setByCSPRNG();
    }
    return ch;
}


bool verify2(
    const Fr v1,
    const Fr v2,
    const Fr ch,
    const std::array<G2, 4>& Y_bar,
    const G2& sigma_bar,
    const Fr comm) {

    G2 R_bar;
    G2 term1;
    G2::mul(term1, Y_bar[2], v1);


    G2 term2;
    G2::mul(term2, Y_bar[3], v2);

    G2 term3;
    G2::mul(term1, sigma_bar, ch);


    R_bar = term1;
    R_bar += term2;
    R_bar += term3;

    // std::vector<unsigned char> R_bar_data;
    unsigned char R_bar_data[96];
    R_bar.serialize(R_bar_data, 96);
    // R_bar.serialize(R_bar_data);
    Fr comm_bar;
    comm_bar.setHashOf(R_bar_data,96);

    return comm_bar == comm;
}


int main() {
    // setup parameter
    initPairing();
    // global_initialize();

    G1 P;
    G2 Q;
    // G1::hashAndMapTo(P, "P");
    Hash(P, "P");
    // G2::hashAndMapTo(Q, "Q");
    Hash(Q, "Q");

    std::pair<PublicKey, SecretKey> keypair = generateKeyPair(P, Q);
    PublicKey pk = keypair.first;
    SecretKey sk = keypair.second;

    Fr x;
    x.setByCSPRNG();

    Fr omega;
    omega.setByCSPRNG();
    Fr alpha;
    alpha.setByCSPRNG();
    Fr beta;
    beta.setByCSPRNG();


    G1 h_prime;
    Hash(h_prime, "h_prime");


    G1 sigma = sign(h_prime, sk.fr_keys, x, omega);



    auto start = steady_clock::now();

    for (int i = 0; i < 1000; ++i) {

        std::pair<G2, Fr> proof1 = prove1(pk.g2_keys, x, omega, alpha, beta);

        G2 sigma_bar= proof1.first;
        Fr comm = proof1.second;



        Fr ch = verify1(pk.g2_keys,sigma,h_prime, sigma_bar, Q);


        Fr tmp1;
        Fr v1;
        Fr::mul(tmp1, ch, x);
        Fr::sub(v1, alpha, tmp1);

        Fr tmp2;
        Fr v2;
        Fr::mul(tmp2, ch, omega);
        Fr::sub(v2, beta, tmp2);



        bool verify_result = verify2(v1, v2, ch, pk.g2_keys, sigma_bar, comm);
    }

    auto end = steady_clock::now();

    std::chrono::duration<double, std::milli> duration_ms = end - start;
    std::cout << "time: "
              << std::fixed << std::setprecision(2)
              << duration_ms.count()
              << " ms" << std::endl;

    return 0;





}




