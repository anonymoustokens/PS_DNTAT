from hashlib import sha256
from functools import reduce
from ec import ECPoint, FQ
from hash_to_point import hash_to_point
from utils import serialize, multi_controller, controller, timing_decorator, byte_count_decorator,multi_controller_threaded
import time
from contextlib import contextmanager


from py_ecc.bn128 import neg, add, multiply, FQ12 


@contextmanager
def timed_step(step_name):
    start = time.perf_counter()  
    yield
    elapsed_ms = (time.perf_counter() - start) * 1000 
    print(f"{step_name}: {elapsed_ms:.2f}ms")


class DNTAT_PS:
    def __init__(self, ec_point: ECPoint, fq: FQ, num_signers):
        self.ec_point = ec_point
        self.fq = fq
        self.g1 = ec_point.G1()
        self.g2 = ec_point.G2()
        self.neg_g2 = ec_point(neg(ec_point.G2().p))

        self.num_signers = num_signers # TODO: inconsistent naming across implementations
        self.hash = lambda x: sha256(x).digest()
        self.domain = self.hash(b"DOMAIN_BM_BLS")

    def H_1(self, *args):
        return self.hash(serialize(args)+b'1')
    
    def H_2(self, *args):
        return self.hash(serialize(args)+b'2')
    
    def H_3(self, *args):
        return self.hash(serialize(args)+b'3')
    

    def bytes_to_fq(self, data: bytes):
    # Step 1: 
        integer_val = int.from_bytes(data, byteorder="big")
    
    # Step 2: 
        q = self.fq.curve_order()  
        mod_val = integer_val % q
    
    # Step 3:
        return self.fq(mod_val)
    
    
    
    def H(self, *args):
        return self.ec_point(hash_to_point(serialize(args), self.domain))

    def _H(self, *args):
        return int.from_bytes(
            self.hash(serialize(args)),
            'big'
        )

    def H_agg(self, *args):
        return self.fq(self._H('agg', *args))

    # def S_keygen(self):
    #     sks = []
    #     pks = []
    #     for _ in range(self.num_signers):
    #         sk = self.fq.rand()
    #         sks.append(sk)
    #         pk = (self.g1 * sk, self.ec_point(multiply(self.g2.p, sk.n)))
    #         pks.append(pk)

    #     return (pks, sks) # TODO: inconsistent order (sks, pks) / (pks, sks)
    

    def S_keygen(self):
        sks = []  
        pks = [] 

        for _ in range(self.num_signers):
      
            sk = [self.fq.rand() for _ in range(4)]
            sks.append(tuple(sk))

      
            pk_g1 = [self.g1 * y for y in sk]   
            pk_g2 = [self.ec_point(multiply(self.g2.p, y.n))  for y in sk]   

       
            pks.append(tuple(pk_g1 + pk_g2))

        return (pks, sks)



    def U_keygen(self):
        sku = self.fq.rand()
        pku = self.g1 * sku
        return (pku, sku)

    def _a(self, pks):
        a = [
            self.H_agg(
                list(map(lambda pk: pk[4], pks)),
                pks[signer_index][4]
            )
            for signer_index in range(self.num_signers)
        ]
        return a

    def keyaggr(self, pks):
        a = self._a(pks)
        apk1 = self.ec_point(reduce(add, [
            multiply(pks[signer_index][4].p, a[signer_index].n)
            for signer_index in range(self.num_signers)
        ]))
        apk2 = self.ec_point(reduce(add, [
            multiply(pks[signer_index][5].p, a[signer_index].n)
            for signer_index in range(self.num_signers)
        ]))
        apk3 = self.ec_point(reduce(add, [
            multiply(pks[signer_index][6].p, a[signer_index].n)
            for signer_index in range(self.num_signers)
        ]))
        apk4 = self.ec_point(reduce(add, [
            multiply(pks[signer_index][7].p, a[signer_index].n)
            for signer_index in range(self.num_signers)
        ]))

        return [apk1, apk2, apk3, apk4]


    def S_sign(self, sk, pku):
        h,resp, ch, T = yield
        
        comm_1_bar = h * resp[0] + self.g1 * resp[1] + T[0] * ch
        comm_2_bar = T[0] * resp[5] + self.g1 * resp[2] + T[1] * ch
        comm_3_bar = T[0] * resp[6] + self.g1 * resp[3] + T[2] * ch
        comm_4_bar = T[0] * resp[7] + self.g1 * resp[4] + T[3] * ch
        comm_5_bar = self.g1 * resp[6] + pku * ch
        ch_bar = BN128FQ(int.from_bytes(self.H_1(self.g1, h, comm_1_bar, comm_2_bar, comm_3_bar, comm_4_bar, comm_5_bar, T[0], T[1], T[2], T[3], pku)))
        if ch != ch_bar:
            raise ValueError("ABORT")
        s_bar = T[0]*sk[0] +T[1]*sk[1] + T[2]*sk[2] + T[3]*sk[3] 
        yield s_bar

    def U_sign(self, pku, sku, pks, S):
        sigma_bars = []
        random1 = self.fq.rand()
        h = self.g1 * random1
        r_1 = self.fq.rand()
        r_2 = self.fq.rand()
        r_3 = self.fq.rand()
        r_4 = self.fq.rand()
        r_5 = self.fq.rand()


        hbar = h * r_1
        theta = self.bytes_to_fq(self.H_3(hbar))
        
        omega = self.fq.rand()

        T_1= h * r_1 + self.g1 * r_2
        T_2= T_1 * theta + self.g1 * r_3
        T_3= T_1 * sku + self.g1 * r_4
        T_4= T_1 * omega + self.g1 * r_5


        
        a = self.fq.rand()
        b = self.fq.rand()
        c = self.fq.rand()
        d = self.fq.rand()
        e = self.fq.rand()
        f = self.fq.rand()
        m = self.fq.rand()
        n = self.fq.rand()

        comm_1 = h * a + self.g1 * b
        comm_2 = T_1 * f + self.g1 * c
        comm_3 = T_1 * m + self.g1 * d
        comm_4 = T_1 * n + self.g1 * e
        comm_5 = self.g1 * m


        ch = BN128FQ(int.from_bytes(self.H_1(self.g1, h, comm_1, comm_2, comm_3, comm_4,comm_5, T_1, T_2, T_3,T_4, pku)))
       
        resp_1 = a.__sub__(ch * r_1)
        resp_2 = b.__sub__(ch * r_2)
        resp_3 = c.__sub__(ch * r_3)
        resp_4 = d.__sub__(ch * r_4)
        resp_5 = e.__sub__(ch * r_5)
        resp_6 = f.__sub__(ch * theta)
        resp_7 = m.__sub__(ch * sku)
        resp_8 = n.__sub__(ch * omega)

        resp = (resp_1, resp_2, resp_3, resp_4, resp_5, resp_6, resp_7, resp_8)
        T = (T_1, T_2, T_3, T_4)

        for i, s in enumerate(S):
            s_bar = s.send((h,resp, ch, T))
            pk_i0_neg = [self.ec_point.neg(pks[i][0]), self.ec_point.neg(pks[i][1]), self.ec_point.neg(pks[i][2]), self.ec_point.neg(pks[i][3])]
            sigma_bar = s_bar + pk_i0_neg[0] * r_2+ pk_i0_neg[1] * theta * (r_2)+ pk_i0_neg[1] * (r_3)  + pk_i0_neg[2] * sku * (r_2) + pk_i0_neg[2] * (r_4) + pk_i0_neg[3] * omega * (r_2) + pk_i0_neg[3] * (r_5)
            sigma_bars.append(sigma_bar)




        # a = self._a(pks)
        # sigma = self.ec_point.sum([sigma_bars[s] * a[s] for s in range(self.num_signers)])
        # token = (omega, hbar, sigma)
        yield sigma_bars,hbar,omega

    def sign(self, sks, pks, sku, pku):
        return multi_controller(
            lambda *args: self.U_sign(pku, sku, pks, *args),
            [(lambda sk: lambda *args: self.S_sign(sk, pku, *args))(sks[i]) for i in range(self.num_signers)]
        )
    

    def tokenaggr(self, sigma_bars,hbar,omega, pks):
        a = self._a(pks)
        sigma = self.ec_point.sum([sigma_bars[s] * a[s] for s in range(self.num_signers)])
        token = (omega, hbar, sigma)
        return token 






    def verify(self, token, apk, sku):
  
        return controller(
          lambda: self.User_verify(token, apk, sku),
          lambda: self.Server_verify(token, apk)  
       )
    
    def Server_verify(self, token, apk):
        omega, hbar, sigma = token
        thetabar =  self.bytes_to_fq(self.H_3(hbar))
        sigma1 = self.ec_point(reduce(add, [multiply(apk[0].p, 1) , multiply(apk[1].p, thetabar.n)]))
        try:
            sigma_bar, comm = yield
        except StopIteration:
            raise ValueError("ABORT")
        
        sigma2 = self.ec_point(reduce(add, [sigma1.p , sigma_bar.p]))
        if (not self.ec_point.pairing(sigma, self.neg_g2, hbar, sigma2)):
            raise ValueError("ABORT")
        
        ch = self.fq.rand()
        v1,v2, rho = yield ch

        R_bar = self.ec_point(reduce(add, [multiply(apk[2].p, v1.n), multiply(apk[3].p, v2.n), multiply(sigma_bar.p, ch.n)]))
        comm_bar = self.H_2(R_bar, rho)
        yield comm == comm_bar

    def User_verify(self, token, apk, sku):
        omega, hbar, sigma = token
        sigma_bar = self.ec_point(reduce(add, [multiply(apk[2].p, sku.n) , multiply(apk[3].p, omega.n)]))
        alpha = self.fq.rand()
        beta = self.fq.rand()
        R = self.ec_point(reduce(add, [multiply(apk[2].p, alpha.n) , multiply(apk[3].p, beta.n)]))
        rho = self.fq.rand()
        comm = self.H_2(R, rho)
        ch = yield (sigma_bar, comm)
        v1 = alpha - ch * sku
        v2 = beta - ch * omega

        yield (v1,v2, rho)

    def Sigma_bar(self, apk, sku, omega, hbar):
        sigma1 = self.ec_point(reduce(add, [multiply(apk[0].p, 1) , multiply(apk[1].p, self.bytes_to_fq(self.H_3(hbar)).n)]))
        sigma2 = self.ec_point(reduce(add, [sigma1.p , multiply(apk[2].p, sku.n) , multiply(apk[3].p, omega.n)]))
        return sigma2







import unittest
from ec import from_ecc_py
import py_eth_pairing
BN128FQ, BN128Point = from_ecc_py('BN128', py_eth_pairing)

class TestDNTAT_PS(unittest.TestCase):



    def test(self):
        num_signers = 4
        with timed_step("setup DNTAT_PS"):
            dntat = DNTAT_PS(BN128Point, BN128FQ, num_signers)
        with timed_step(" S keygen"):
            (pks, sks) = dntat.S_keygen()
        with timed_step(" U keygen"):
            (pku, sku) = dntat.U_keygen()
        
        apk = dntat.keyaggr(pks)
        with timed_step("sign"):
            sigma_bars,hbar,omega = dntat.sign(sks, pks, sku, pku)
        with timed_step("aggr"):
            token = dntat.tokenaggr(sigma_bars,hbar,omega, pks)

        with timed_step("redemption"):
            dntat.verify(token, apk, sku)




