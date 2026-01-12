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

    function _sign(
        bytes32 hash,
        uint256 deadline
    ) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                baseProof.DOMAIN_SEPARATOR(),
                keccak256(
                    abi.encode(baseProof.PROOF_TYPEHASH(), hash, deadline)
                )
            )
        );
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

        (
            bool submitted,
            ,
            uint128 timestamp,
            uint128 userIndex,
            bytes32 storedMeta
        ) = baseProof.getProofData(proofHash);
        assertEq(storedMeta, metadataHash);
        assertTrue(submitted);
        assertEq(userIndex, 0);
        assertEq(timestamp, block.timestamp);
    }

    function test_RevertWhen_DuplicateProof() public {
        bytes32 proofHash = keccak256("test proof");
        bytes32 metadataHash = keccak256("json metadata");
        uint256 dl = block.timestamp + 100;
        (uint8 v, bytes32 r, bytes32 s) = _sign(proofHash, dl);

        vm.prank(user1);
        baseProof.submitProof(proofHash, metadataHash, dl, v, r, s);

        vm.prank(user2);
        vm.expectRevert(
            abi.encodeWithSelector(
                IBaseProof.ProofAlreadySubmitted.selector,
                proofHash
            )
        );
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

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                baseProof.DOMAIN_SEPARATOR(),
                keccak256(
                    abi.encode(
                        baseProof.BATCH_TYPEHASH(),
                        keccak256(abi.encodePacked(proofHashes)),
                        dl
                    )
                )
            )
        );
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

    function test_BatchEventEmitted() public {
        bytes32[] memory proofHashes = new bytes32[](2);
        proofHashes[0] = keccak256("proof 1");
        proofHashes[1] = keccak256("proof 2");
        bytes32[] memory metaHashes = new bytes32[](2);
        metaHashes[0] = keccak256("meta 1");
        metaHashes[1] = keccak256("meta 2");

        uint256 dl = block.timestamp + 100;

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                baseProof.DOMAIN_SEPARATOR(),
                keccak256(
                    abi.encode(
                        baseProof.BATCH_TYPEHASH(),
                        keccak256(abi.encodePacked(proofHashes)),
                        dl
                    )
                )
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(verPrivateKey, digest);

        vm.prank(user1);
        vm.expectEmit(true, false, false, true);
        emit IBaseProof.BatchProofSubmitted(user1, 2, block.timestamp);

        baseProof.submitProofBatch(proofHashes, metaHashes, dl, v, r, s);
    }

    /*
    function test_RevertWhen_DuplicateProof() public {
        bytes32 proofHash = keccak256("test proof");
        bytes32 metadataHash = keccak256("json metadata");
        uint256 dl = block.timestamp + 100;
        (uint8 v, bytes32 r, bytes32 s) = _sign(proofHash, dl);

        vm.prank(user1);
        baseProof.submitProof(proofHash, metadataHash, dl, v, r, s);

        vm.prank(user2);
        vm.expectRevert(
            abi.encodeWithSelector(
                IBaseProof.ProofAlreadySubmitted.selector,
                proofHash
            )
        );
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

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                baseProof.DOMAIN_SEPARATOR(),
                keccak256(
                    abi.encode(
                        baseProof.BATCH_TYPEHASH(),
                        keccak256(abi.encodePacked(proofHashes)),
                        dl
                    )
                )
            )
        );
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

    // Batch submission tests

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
        vm.expectRevert(
            abi.encodeWithSelector(BaseProof.DuplicateInBatch.selector, 2)
        );
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
        vm.expectRevert(
            abi.encodeWithSelector(
                BaseProof.ProofAlreadySubmitted.selector,
                existingHash
            )
        );
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

        (bool submitted, uint128 timestamp, uint128 userIndex) = baseProof
            .getProofData(proofHash);
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

    function testFuzz_BatchSubmission(bytes32[] calldata proofHashes) public {
        if (proofHashes.length == 0) {
            vm.expectRevert(BaseProof.EmptyBatch.selector);
            baseProof.submitProofBatch(proofHashes);
            return;
        }

        // Remove duplicates for valid test
        bool hasDuplicates = false;
        for (uint256 i = 0; i < proofHashes.length; ++i) {
            for (uint256 j = i + 1; j < proofHashes.length; ++j) {
                if (proofHashes[i] == proofHashes[j]) {
                    hasDuplicates = true;
                    break;
                }
            }
            if (hasDuplicates) break;
        }

        if (hasDuplicates) {
            // Skip test if duplicates exist
            return;
        }

        vm.prank(user1);
        baseProof.submitProofBatch(proofHashes);

        assertEq(baseProof.userProofCount(user1), uint128(proofHashes.length));
        assertEq(baseProof.totalProofs(), uint128(proofHashes.length));
    }
    */
}
