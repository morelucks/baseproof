// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/// @title BaseProof
/// @notice Trust-minimized action proofs on Base
/// @dev Stores cryptographic proof hashes and prevents duplicates
contract BaseProof {
    /// @notice Emitted when a proof is submitted
    /// @param user The address that submitted the proof
    /// @param proofHash The hash of the proof
    /// @param timestamp The block timestamp when the proof was submitted
    event ProofSubmitted(
        address indexed user,
        bytes32 indexed proofHash,
        uint256 timestamp
    );

    /// @notice Mapping to track submitted proof hashes
    /// @dev proofHash => true if already submitted
    mapping(bytes32 => bool) public proofs;

    /// @notice Mapping to track proof count per user
    /// @dev user => count of proofs submitted
    mapping(address => uint256) public userProofCount;

    /// @notice Total number of proofs submitted
    uint256 public totalProofs;

    /// @notice Submit a proof hash
    /// @param proofHash The hash of the proof to submit
    /// @dev Reverts if the proof hash has already been submitted
    function submitProof(bytes32 proofHash) external {
        require(!proofs[proofHash], "BaseProof: proof already submitted");

        proofs[proofHash] = true;
        userProofCount[msg.sender]++;
        totalProofs++;

        emit ProofSubmitted(msg.sender, proofHash, block.timestamp);
    }

    /// @notice Check if a proof hash has been submitted
    /// @param proofHash The proof hash to check
    /// @return true if the proof has been submitted, false otherwise
    function isProofSubmitted(bytes32 proofHash) external view returns (bool) {
        return proofs[proofHash];
    }

    /// @notice Get the number of proofs submitted by a user
    /// @param user The address to query
    /// @return The number of proofs submitted by the user
    function getUserProofCount(address user) external view returns (uint256) {
        return userProofCount[user];
    }
}

