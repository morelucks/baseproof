// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {BaseProof} from "../src/BaseProof.sol";
import {IBaseProof} from "../src/IBaseProof.sol";

contract BaseProofTest is Test {
    BaseProof public baseProof;

    address public user1 = address(0x1);
    address public user2 = address(0x2);
    uint256 public verPrivateKey = 0x1234;
    address public verifier;

    function setUp() public {
        verifier = vm.addr(verPrivateKey);
        baseProof = new BaseProof(verifier);
    }

    function _sign(bytes32 hash, uint256 deadline) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", baseProof.DOMAIN_SEPARATOR(), keccak256(abi.encode(baseProof.PROOF_TYPEHASH(), hash, deadline))));
        (v, r, s) = vm.sign(verPrivateKey, digest);
    }

    function test_SubmitProof() public {
        bytes32 proofHash = keccak256("test proof");
        bytes32 metadataHash = keccak256("json metadata");
        uint256 dl = block.timestamp + 100;
        (uint8 v, bytes32 r, bytes32 s) = _sign(proofHash, dl);
        
        vm.prank(user1);
        baseProof.submitProof(proofHash, metadataHash, dl, v, r, s);

        assertTrue(baseProof.isProofSubmitted(proofHash));
        assertEq(baseProof.userProofCount(user1), 1);
        assertEq(baseProof.totalProofs(), 1);
        
        (,,,, bytes32 storedMeta) = baseProof.getProofData(proofHash);
        assertEq(storedMeta, metadataHash);
    }

    function test_RevertWhen_DuplicateProof() public {
        bytes32 proofHash = keccak256("test proof");
        bytes32 metadataHash = keccak256("json metadata");
        uint256 dl = block.timestamp + 100;
        (uint8 v, bytes32 r, bytes32 s) = _sign(proofHash, dl);
        
        vm.prank(user1);
        baseProof.submitProof(proofHash, metadataHash, dl, v, r, s);

        vm.prank(user2);
        vm.expectRevert(abi.encodeWithSelector(IBaseProof.ProofAlreadySubmitted.selector, proofHash));
        baseProof.submitProof(proofHash, metadataHash, dl, v, r, s);
    }

    function test_SubmitProofBatch() public {
        bytes32[] memory proofHashes = new bytes32[](3);
        bytes32[] memory metaHashes = new bytes32[](3);
        proofHashes[0] = keccak256("batch 1");
        proofHashes[1] = keccak256("batch 2");
        proofHashes[2] = keccak256("batch 3");
        metaHashes[0] = keccak256("param 1");
        metaHashes[1] = keccak256("param 2");
        metaHashes[2] = keccak256("param 3");
        
        uint256 dl = block.timestamp + 100;
        
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", baseProof.DOMAIN_SEPARATOR(), keccak256(abi.encode(baseProof.BATCH_TYPEHASH(), keccak256(abi.encodePacked(proofHashes)), dl))));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(verPrivateKey, digest);

        vm.prank(user1);
        baseProof.submitProofBatch(proofHashes, metaHashes, dl, v, r, s);

        assertTrue(baseProof.isProofSubmitted(proofHashes[0]));
        assertTrue(baseProof.isProofSubmitted(proofHashes[1]));
        assertTrue(baseProof.isProofSubmitted(proofHashes[2]));
        assertEq(baseProof.userProofCount(user1), 3);
        assertEq(baseProof.totalProofs(), 3);
    }

    function test_RevertWhen_BadSigner() public {
        bytes32 h = keccak256("bad"); 
        bytes32 m = keccak256("meta");
        uint256 dl = block.timestamp + 100;
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xBEEF, keccak256("dgst"));
        vm.prank(user1);
        vm.expectRevert(IBaseProof.InvalidSignature.selector);
        baseProof.submitProof(h, m, dl, v, r, s);
    }

    function test_Revocation() public {
        bytes32 proofHash = keccak256("to revoke");
        bytes32 metadataHash = keccak256("json metadata");
        uint256 dl = block.timestamp + 100;
        (uint8 v, bytes32 r, bytes32 s) = _sign(proofHash, dl);
        
        baseProof.submitProof(proofHash, metadataHash, dl, v, r, s);
        assertTrue(baseProof.isProofSubmitted(proofHash));

        baseProof.revokeProof(proofHash);
        
        assertFalse(baseProof.isProofSubmitted(proofHash)); // Should return false if revoked
        assertTrue(baseProof.isProofRevoked(proofHash));
    }

    function test_RevertWhen_RevokeUnauthorized() public {
        bytes32 proofHash = keccak256("to revoke");
        bytes32 metadataHash = keccak256("json metadata");
        uint256 dl = block.timestamp + 100;
        (uint8 v, bytes32 r, bytes32 s) = _sign(proofHash, dl);
        
        baseProof.submitProof(proofHash, metadataHash, dl, v, r, s);
        
        vm.prank(user2);
        vm.expectRevert(IBaseProof.Unauthorized.selector);
        baseProof.revokeProof(proofHash);
    }
}
