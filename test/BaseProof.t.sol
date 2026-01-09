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

    // Batch submission tests
    function test_SubmitProofBatch() public {
        bytes32[] memory proofHashes = new bytes32[](3);
        proofHashes[0] = keccak256("proof 1");
        proofHashes[1] = keccak256("proof 2");
        proofHashes[2] = keccak256("proof 3");

        vm.prank(user1);
        baseProof.submitProofBatch(proofHashes);

        assertTrue(baseProof.isProofSubmitted(proofHashes[0]));
        assertTrue(baseProof.isProofSubmitted(proofHashes[1]));
        assertTrue(baseProof.isProofSubmitted(proofHashes[2]));
        assertEq(baseProof.userProofCount(user1), 3);
        assertEq(baseProof.totalProofs(), 3);
    }

    function test_BatchEventEmitted() public {
        bytes32[] memory proofHashes = new bytes32[](2);
        proofHashes[0] = keccak256("proof 1");
        proofHashes[1] = keccak256("proof 2");

        vm.prank(user1);
        vm.expectEmit(true, false, false, true);
        emit BaseProof.BatchProofSubmitted(user1, 2, block.timestamp);

        baseProof.submitProofBatch(proofHashes);
    }

    function test_RevertWhen_EmptyBatch() public {
        bytes32[] memory proofHashes = new bytes32[](0);

        vm.prank(user1);
        vm.expectRevert(BaseProof.EmptyBatch.selector);
        baseProof.submitProofBatch(proofHashes);
    }

    function test_RevertWhen_DuplicateInBatch() public {
        bytes32[] memory proofHashes = new bytes32[](3);
        proofHashes[0] = keccak256("proof 1");
        proofHashes[1] = keccak256("proof 2");
        proofHashes[2] = keccak256("proof 1"); // duplicate

        vm.prank(user1);
        vm.expectRevert(abi.encodeWithSelector(BaseProof.DuplicateInBatch.selector, 2));
        baseProof.submitProofBatch(proofHashes);
    }

    function test_RevertWhen_BatchContainsExistingProof() public {
        bytes32 existingHash = keccak256("existing proof");
        bytes32[] memory proofHashes = new bytes32[](2);
        proofHashes[0] = keccak256("new proof");
        proofHashes[1] = existingHash;

        vm.prank(user1);
        baseProof.submitProof(existingHash);

        vm.prank(user2);
        vm.expectRevert(abi.encodeWithSelector(BaseProof.ProofAlreadySubmitted.selector, existingHash));
        baseProof.submitProofBatch(proofHashes);
    }

    function test_MixedIndividualAndBatch() public {
        bytes32 individualHash = keccak256("individual");
        bytes32[] memory batchHashes = new bytes32[](2);
        batchHashes[0] = keccak256("batch 1");
        batchHashes[1] = keccak256("batch 2");

        vm.prank(user1);
        baseProof.submitProof(individualHash);

        vm.prank(user1);
        baseProof.submitProofBatch(batchHashes);

        assertEq(baseProof.userProofCount(user1), 3);
        assertEq(baseProof.totalProofs(), 3);
    }

    // getProofData tests
    function test_GetProofData() public {
        bytes32 proofHash = keccak256("test proof");

        (bool submitted, uint128 timestamp, uint128 userIndex) = baseProof.getProofData(proofHash);
        assertFalse(submitted);
        assertEq(timestamp, 0);
        assertEq(userIndex, 0);

        vm.prank(user1);
        baseProof.submitProof(proofHash);

        (submitted, timestamp, userIndex) = baseProof.getProofData(proofHash);
        assertTrue(submitted);
        assertEq(timestamp, block.timestamp);
        assertEq(userIndex, 0);
    }

    function test_GetProofData_MultipleProofs() public {
        bytes32 proofHash1 = keccak256("proof 1");
        bytes32 proofHash2 = keccak256("proof 2");

        vm.prank(user1);
        baseProof.submitProof(proofHash1);

        vm.prank(user1);
        baseProof.submitProof(proofHash2);

        (, , uint128 userIndex1) = baseProof.getProofData(proofHash1);
        (, , uint128 userIndex2) = baseProof.getProofData(proofHash2);

        assertEq(userIndex1, 0);
        assertEq(userIndex2, 1);
    }

    function test_GetUserProofCount() public {
        assertEq(baseProof.getUserProofCount(user1), 0);

        bytes32 proofHash = keccak256("test proof");
        vm.prank(user1);
        baseProof.submitProof(proofHash);

        assertEq(baseProof.getUserProofCount(user1), 1);
    }

    function test_MultipleUsers() public {
        bytes32 proofHash1 = keccak256("user1 proof");
        bytes32 proofHash2 = keccak256("user2 proof");

        vm.prank(user1);
        baseProof.submitProof(proofHash1);

        vm.prank(user2);
        baseProof.submitProof(proofHash2);

        assertEq(baseProof.userProofCount(user1), 1);
        assertEq(baseProof.userProofCount(user2), 1);
        assertEq(baseProof.totalProofs(), 2);
    }
}

