// Optimized Test Suite
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {BaseProof} from "../src/BaseProof.sol";

/// @title BaseProofTest
/// @notice Test suite for BaseProof contract
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

    function test_SubmitProof() public {
        bytes32 proofHash = keccak256("test proof");
        
        vm.prank(user1);
        uint256 dl = block.timestamp + 100; (uint8 v, bytes32 r, bytes32 s) = _sign(proofHash, dl); baseProof.submitProof(proofHash, dl, v, r, s);

        assertTrue(baseProof.isProofSubmitted(proofHash));
        assertEq(baseProof.userProofCount(user1), 1);
        assertEq(baseProof.totalProofs(), 1);
    }

    function test_RevertWhen_DuplicateProof() public {
        bytes32 proofHash = keccak256("test proof");
        
        vm.prank(user1);
        uint256 dl = block.timestamp + 100; (uint8 v, bytes32 r, bytes32 s) = _sign(proofHash, dl); baseProof.submitProof(proofHash, dl, v, r, s);

        vm.prank(user2);
        vm.expectRevert(abi.encodeWithSelector(BaseProof.ProofAlreadySubmitted.selector, proofHash));
        uint256 dl = block.timestamp + 100; (uint8 v, bytes32 r, bytes32 s) = _sign(proofHash, dl); baseProof.submitProof(proofHash, dl, v, r, s);
    }

    function test_MultipleProofsFromSameUser() public {
        bytes32 proofHash1 = keccak256("proof 1");
        bytes32 proofHash2 = keccak256("proof 2");
        
        vm.prank(user1);
        baseProof.submitProof(proofHash1);

        vm.prank(user1);
        baseProof.submitProof(proofHash2);

        assertEq(baseProof.userProofCount(user1), 2);
        assertEq(baseProof.totalProofs(), 2);
    }

    function test_EventEmitted() public {
        bytes32 proofHash = keccak256("test proof");
        
        vm.prank(user1);
        vm.expectEmit(true, true, false, true);
        emit BaseProof.ProofSubmitted(user1, proofHash, block.timestamp);
        
        uint256 dl = block.timestamp + 100; (uint8 v, bytes32 r, bytes32 s) = _sign(proofHash, dl); baseProof.submitProof(proofHash, dl, v, r, s);
    }

    function testFuzz_SubmitProof(bytes32 proofHash) public {
        vm.prank(user1);
        uint256 dl = block.timestamp + 100; (uint8 v, bytes32 r, bytes32 s) = _sign(proofHash, dl); baseProof.submitProof(proofHash, dl, v, r, s);

        assertTrue(baseProof.isProofSubmitted(proofHash));
        assertEq(baseProof.userProofCount(user1), 1);
    }

    function testFuzz_RevertWhen_DuplicateProof(bytes32 proofHash) public {
        vm.prank(user1);
        uint256 dl = block.timestamp + 100; (uint8 v, bytes32 r, bytes32 s) = _sign(proofHash, dl); baseProof.submitProof(proofHash, dl, v, r, s);

        vm.prank(user2);
        vm.expectRevert(abi.encodeWithSelector(BaseProof.ProofAlreadySubmitted.selector, proofHash));
        uint256 dl = block.timestamp + 100; (uint8 v, bytes32 r, bytes32 s) = _sign(proofHash, dl); baseProof.submitProof(proofHash, dl, v, r, s);
    }
}


    // Batch Submission Tests
    function test_SubmitProofBatch() public {
        bytes32[] memory proofHashes = new bytes32[](3);
        proofHashes[0] = keccak256("batch 1");
        proofHashes[1] = keccak256("batch 2");
        proofHashes[2] = keccak256("batch 3");

        vm.prank(user1);
        baseProof.submitProofBatch(proofHashes);

        assertTrue(baseProof.isProofSubmitted(proofHashes[0]));
        assertTrue(baseProof.isProofSubmitted(proofHashes[1]));
        assertTrue(baseProof.isProofSubmitted(proofHashes[2]));
        assertEq(baseProof.userProofCount(user1), 3);
        assertEq(baseProof.totalProofs(), 3);
    }
    function test_RevertWhen_EmptyBatch() public {
        bytes32[] memory emptyBatch = new bytes32[](0);
        
        vm.prank(user1);
        vm.expectRevert(BaseProof.EmptyBatch.selector);
        baseProof.submitProofBatch(emptyBatch);
    }
    function test_RevertWhen_DuplicateInBatch() public {
        bytes32[] memory proofHashes = new bytes32[](2);
        proofHashes[0] = keccak256("duplicate");
        proofHashes[1] = keccak256("duplicate");

        vm.prank(user1);
        vm.expectRevert(abi.encodeWithSelector(BaseProof.DuplicateInBatch.selector, 1));
        baseProof.submitProofBatch(proofHashes);
    }
    function test_RevertWhen_BatchContainsExisting() public {
        bytes32 proofHash = keccak256("existing");
        
        vm.prank(user1);
        uint256 dl = block.timestamp + 100; (uint8 v, bytes32 r, bytes32 s) = _sign(proofHash, dl); baseProof.submitProof(proofHash, dl, v, r, s);

        bytes32[] memory proofHashes = new bytes32[](2);
        proofHashes[0] = proofHash;
        proofHashes[1] = keccak256("new");

        vm.prank(user1);
        vm.expectRevert(abi.encodeWithSelector(BaseProof.ProofAlreadySubmitted.selector, proofHash));
        baseProof.submitProofBatch(proofHashes);

    function _sign(bytes32 hash, uint256 deadline) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", baseProof.DOMAIN_SEPARATOR(), keccak256(abi.encode(baseProof.PROOF_TYPEHASH(), hash, deadline))));
        (v, r, s) = vm.sign(verPrivateKey, digest);
    }

    function test_RevertWhen_BadSigner() public {
        bytes32 h = keccak256("bad"); uint256 dl = block.timestamp + 100;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xBEEF, keccak256("dgst"));
        vm.expectRevert(BaseProof.InvalidSignature.selector);
        baseProof.submitProof(h, dl, v, r, s);
    }
}
