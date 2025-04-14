import os
import json
from hashlib import sha256
from ec import from_ecc_py
import py_eth_pairing
from dntat_ps import DNTAT_PS
BN128FQ, BN128Point = from_ecc_py('BN128', py_eth_pairing)


def generate_dntat_ps_fixture(num_signers):
    dntat = DNTAT_PS(BN128Point, BN128FQ, num_signers)
    (pks, sks) = dntat.S_keygen()
    (pku, sku) = dntat.U_keygen()
    apk = dntat.keyaggr(pks)
    token = dntat.sign(sks, pks, sku, pku)
    omega,hbar, sigma = token
    sigma_bar = dntat.Sigma_bar(apk, sku, omega, hbar)
    assert  dntat.verify(token, apk, sku)
    write_dntat_ps_fixture(sigma_bar, hbar, sigma)

def write_dntat_ps_fixture(sigma_bar, h, sigma):
    a, b = sigma_bar.p
    sigma_bar = [*a.coeffs, *b.coeffs]
    data = {
        "sigma_bar": list(map(lambda fq: fq.n, sigma_bar)), # TODO: clean up
        "hbar": h.p,
        "sigma": sigma.p,
    }

    with open('data/input_dntat.json', 'w') as f:
        json.dump(data, f)


if __name__ == '__main__':
    num_signers = int(os.environ.get('NUM_SIGNERS', 1))
    generate_dntat_ps_fixture(num_signers)
