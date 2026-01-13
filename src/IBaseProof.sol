// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

interface IBaseProof {
    /// @notice Custom error for duplicate proof submission
    error ProofAlreadySubmitted(bytes32 proofHash);

    /// @notice Custom error for empty batch submission
    error EmptyBatch();

    /// @notice Custom error for duplicate proof in batch
    error DuplicateInBatch(uint256 index);

    error InvalidSignature();
    error DeadlineExpired();
    error Unauthorized();

    /// @notice Emitted when a proof is submitted
    event ProofSubmitted(
        address indexed user,
        bytes32 indexed proofHash,
        uint256 timestamp
    );

    /// @notice Emitted when multiple proofs are submitted in a batch
    event BatchProofSubmitted(
        address indexed user,
        uint256 count,
        uint256 timestamp
    );

    event ProofRevoked(bytes32 indexed proofHash, address indexed user);
    event Paused(address account);
    event Unpaused(address account);
    event VerifierAdded(address indexed verifier);
    event VerifierRemoved(address indexed verifier);
    event OwnershipTransferStarted(
        address indexed previousOwner,
        address indexed newOwner
    );
    event OwnershipTransferred(
        address indexed previousOwner,
        address indexed newOwner
    );

    function submitProof(
        bytes32 proofHash,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;

    function submitProofBatch(
        bytes32[] calldata proofHashes,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;

    function revokeProof(bytes32 proofHash) external;

    function isProofSubmitted(bytes32 proofHash) external view returns (bool);

    function isProofRevoked(bytes32 proofHash) external view returns (bool);

    function getProofData(
        bytes32 proofHash
    )
        external
        view
        returns (
            bool submitted,
            bool revoked,
            uint128 timestamp,
            uint128 userIndex,
            bytes32 metadataHash
        );

    function getUserProofCount(address user) external view returns (uint256);
}
