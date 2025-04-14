// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import {IBLS} from "./interfaces/IBLS.sol";
import {BN254} from "./libs/BN254.sol";

contract DNTAT_PS {
    bytes32 public constant DOMAIN = sha256("DOMAIN_DNTAT_PS");

    IBLS public immutable bls;

    mapping(bytes32 => bool) public usedCredentials;

    constructor(IBLS newBLS) {
        bls = newBLS;
    }

    function verify(
        uint256[4] calldata sigma_bar,
        uint256[2] calldata sigma,
        uint256[2] calldata h
    )
        external
        returns (bool)
    {
        bytes32 credentialHash = sha256(abi.encode(h, sigma));
        require(!usedCredentials[credentialHash], "Credential already used");

        usedCredentials[credentialHash] = true;

        (bool checkSuccess, bool callSuccess) = bls.verifySingle(sigma, sigma_bar, h);
        return callSuccess && checkSuccess;
    }

    
}
