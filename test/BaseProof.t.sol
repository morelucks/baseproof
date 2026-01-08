// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {BaseProof} from "../src/BaseProof.sol";

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
        uint256 dl = block.timestamp + 100;
        (uint8 v, bytes32 r, bytes32 s) = _sign(proofHash, dl);
        
        vm.prank(user1);
        baseProof.submitProof(proofHash, dl, v, r, s);

        assertTrue(baseProof.isProofSubmitted(proofHash));
        assertEq(baseProof.userProofCount(user1), 1);
        assertEq(baseProof.totalProofs(), 1);
    }

    function test_RevertWhen_DuplicateProof() public {
        bytes32 proofHash = keccak256("test proof");
        uint256 dl = block.timestamp + 100;
        (uint8 v, bytes32 r, bytes32 s) = _sign(proofHash, dl);
        
        vm.prank(user1);
        baseProof.submitProof(proofHash, dl, v, r, s);

        vm.prank(user2);
        vm.expectRevert(abi.encodeWithSelector(BaseProof.ProofAlreadySubmitted.selector, proofHash));
        baseProof.submitProof(proofHash, dl, v, r, s);
    }

    function test_SubmitProofBatch() public {
        bytes32[] memory proofHashes = new bytes32[](3);
        proofHashes[0] = keccak256("batch 1");
        proofHashes[1] = keccak256("batch 2");
        proofHashes[2] = keccak256("batch 3");
        uint256 dl = block.timestamp + 100;
        
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", baseProof.DOMAIN_SEPARATOR(), keccak256(abi.encode(baseProof.BATCH_TYPEHASH(), keccak256(abi.encodePacked(proofHashes)), dl))));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(verPrivateKey, digest);

        vm.prank(user1);
        baseProof.submitProofBatch(proofHashes, dl, v, r, s);

        assertTrue(baseProof.isProofSubmitted(proofHashes[0]));
        assertTrue(baseProof.isProofSubmitted(proofHashes[1]));
        assertTrue(baseProof.isProofSubmitted(proofHashes[2]));
        assertEq(baseProof.userProofCount(user1), 3);
        assertEq(baseProof.totalProofs(), 3);
    }

    function test_RevertWhen_BadSigner() public {
        bytes32 h = keccak256("bad"); uint256 dl = block.timestamp + 100;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xBEEF, keccak256("dgst"));
        vm.prank(user1);
        vm.expectRevert(BaseProof.InvalidSignature.selector);
        baseProof.submitProof(h, dl, v, r, s);
    }

    function test_RevertWhen_Expired() public {
        bytes32 h = keccak256("old"); uint256 dl = block.timestamp - 1;
        (uint8 v, bytes32 r, bytes32 s) = _sign(h, dl);
        vm.prank(user1);
        vm.expectRevert(BaseProof.DeadlineExpired.selector);
        baseProof.submitProof(h, dl, v, r, s);
    }

    function test_Ownable2Step() public {
        address newOwner = address(0xDEAF);
        baseProof.transferOwnership(newOwner);
        assertEq(baseProof.owner(), address(this));
        assertEq(baseProof.pendingOwner(), newOwner);

        vm.prank(newOwner);
        baseProof.acceptOwnership();
        assertEq(baseProof.owner(), newOwner);
        assertEq(baseProof.pendingOwner(), address(0));
    }

    function test_Ownership() public {
        address newOwner = address(0xBEEF);
        baseProof.transferOwnership(newOwner);
        assertEq(baseProof.owner(), newOwner);
        
        vm.prank(user1);
        vm.expectRevert(BaseProof.Unauthorized.selector);
        baseProof.setVerifier(user1);
    }

    function test_RevertWhen_Paused() public {
        baseProof.togglePause();
        bytes32 h = keccak256("paused"); uint256 dl = block.timestamp + 100;
        (uint8 v, bytes32 r, bytes32 s) = _sign(h, dl);
        vm.expectRevert(BaseProof.Unauthorized.selector);
        baseProof.submitProof(h, dl, v, r, s);
    }
}
