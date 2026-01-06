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

    function setUp() public {
        baseProof = new BaseProof();
    }

    function test_SubmitProof() public {
        bytes32 proofHash = keccak256("test proof");
        
        vm.prank(user1);
        baseProof.submitProof(proofHash);

        assertTrue(baseProof.isProofSubmitted(proofHash));
        assertEq(baseProof.userProofCount(user1), 1);
        assertEq(baseProof.totalProofs(), 1);
    }

    function test_RevertWhen_DuplicateProof() public {
        bytes32 proofHash = keccak256("test proof");
        
        vm.prank(user1);
        baseProof.submitProof(proofHash);

        vm.prank(user2);
        vm.expectRevert(abi.encodeWithSelector(BaseProof.ProofAlreadySubmitted.selector, proofHash));
        baseProof.submitProof(proofHash);
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
        
        baseProof.submitProof(proofHash);
    }

    function testFuzz_SubmitProof(bytes32 proofHash) public {
        vm.prank(user1);
        baseProof.submitProof(proofHash);

        assertTrue(baseProof.isProofSubmitted(proofHash));
        assertEq(baseProof.userProofCount(user1), 1);
    }

    function testFuzz_RevertWhen_DuplicateProof(bytes32 proofHash) public {
        vm.prank(user1);
        baseProof.submitProof(proofHash);

        vm.prank(user2);
        vm.expectRevert(abi.encodeWithSelector(BaseProof.ProofAlreadySubmitted.selector, proofHash));
        baseProof.submitProof(proofHash);
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
