// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

interface IBaseProof {
    error ProofAlreadySubmitted(bytes32 proofHash);
    error EmptyBatch();
    error DuplicateInBatch(uint256 index);
    error InvalidSignature();
    error DeadlineExpired();
    error Unauthorized();

    event ProofSubmitted(address indexed user, bytes32 indexed proofHash, uint256 timestamp);
    event ProofRevoked(bytes32 indexed proofHash, address indexed revoker);
    event BatchProofSubmitted(address indexed user, uint256 count, uint256 timestamp);
    event Paused(address account);
    event Unpaused(address account);
    event VerifierAdded(address indexed verifier);
    event VerifierRemoved(address indexed verifier);

    function submitProof(
        bytes32 proofHash, 
        bytes32 metadataHash, 
        uint256 deadline, 
        uint8 v, 
        bytes32 r, 
        bytes32 s
    ) external;

    function revokeProof(bytes32 proofHash) external;

    function submitProofBatch(
        bytes32[] calldata proofHashes,
        bytes32[] calldata metadataHashes,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;

    function isProofSubmitted(bytes32 proofHash) external view returns (bool);
}
