// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/// @title BaseProof
/// @notice Trust-minimized action proofs on Base
/// @dev Stores cryptographic proof hashes and prevents duplicates
/// @dev Optimized for gas efficiency on L2
contract BaseProof {
    address public owner;
    address public verifier;
    
    bytes32 public constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 public constant PROOF_TYPEHASH = keccak256("Proof(bytes32 proofHash,uint256 deadline)");
    bytes32 public constant BATCH_TYPEHASH = keccak256("BatchProof(bytes32[] proofHashes,uint256 deadline)");
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
    /// @param user The address that submitted the proof
    /// @param proofHash The hash of the proof
    /// @param timestamp The block timestamp when the proof was submitted
    event ProofSubmitted(
        address indexed user,
        bytes32 indexed proofHash,
        uint256 timestamp
    );

    /// @notice Emitted when multiple proofs are submitted in a batch
    /// @param user The address that submitted the proofs
    /// @param count The number of proofs submitted
    /// @param timestamp The block timestamp when the proofs were submitted
    event BatchProofSubmitted(
        address indexed user,
        uint256 count,
        uint256 timestamp
    );

    /// @notice Packed struct for proof data (gas-optimized storage)
    /// @dev Uses uint128 for counts to save storage (max ~3.4e38 proofs)
    struct ProofData {
        bool submitted;      // 1 byte
        uint128 timestamp;   // 16 bytes - block timestamp when submitted
        uint128 userIndex;   // 16 bytes - index in user's proof list (optional)
    }

    /// @notice Mapping to track submitted proof hashes with metadata
    /// @dev proofHash => ProofData struct
    mapping(bytes32 => ProofData) public proofData;

    /// @notice Mapping to track proof count per user
    /// @dev user => count of proofs submitted
    mapping(address => uint128) public userProofCount;

    /// @notice Total number of proofs submitted
    /// @dev Using uint128 to save gas (max ~3.4e38 proofs)
    uint128 public totalProofs;
    
    constructor(address _verifier) {
        owner = msg.sender;
        verifier = _verifier;
    }

    /// @notice Submit a proof hash
    /// @param proofHash The hash of the proof to submit
    /// @dev Reverts if the proof hash has already been submitted
    /// @dev Emits ProofSubmitted event
    function submitProof(bytes32 proofHash) external {
        ProofData storage data = proofData[proofHash];
        if (data.submitted) revert ProofAlreadySubmitted(proofHash);

        data.submitted = true;
        uint256 currentTimestamp = block.timestamp;
        data.timestamp = uint128(currentTimestamp);
        data.userIndex = userProofCount[msg.sender];
        
        userProofCount[msg.sender]++;
        totalProofs++;

        emit ProofSubmitted(msg.sender, proofHash, currentTimestamp);
    }

    /// @notice Submit multiple proof hashes in a single transaction
    /// @param proofHashes Array of proof hashes to submit
    /// @dev More gas-efficient than multiple individual submissions
    /// @dev Reverts if any proof hash has already been submitted or if duplicates exist in batch
    function submitProofBatch(bytes32[] calldata proofHashes) external {
        uint256 length = proofHashes.length;
        if (length == 0) revert EmptyBatch();

        uint256 timestamp = block.timestamp;
        uint128 userCount = userProofCount[msg.sender];
        uint128 newUserCount = userCount + uint128(length);

        // Check for duplicates in batch and existing proofs
        for (uint256 i = 0; i < length; ++i) {
            bytes32 proofHash = proofHashes[i];
            ProofData storage data = proofData[proofHash];
            
            if (data.submitted) revert ProofAlreadySubmitted(proofHash);
            
            // Check for duplicates within the batch
            for (uint256 j = i + 1; j < length; ++j) {
                if (proofHash == proofHashes[j]) revert DuplicateInBatch(j);
            }

            data.submitted = true;
            data.timestamp = uint128(timestamp);
            data.userIndex = userCount + uint128(i);
        }

        userProofCount[msg.sender] = newUserCount;
        totalProofs += uint128(length);

        emit BatchProofSubmitted(msg.sender, length, timestamp);
    }

    /// @notice Check if a proof hash has been submitted
    /// @param proofHash The proof hash to check
    /// @return true if the proof has been submitted, false otherwise
    function isProofSubmitted(bytes32 proofHash) external view returns (bool) {
        return proofData[proofHash].submitted;
    }

    /// @notice Get proof metadata for a given proof hash
    /// @param proofHash The proof hash to query
    /// @return submitted Whether the proof has been submitted
    /// @return timestamp The timestamp when the proof was submitted (0 if not submitted)
    /// @return userIndex The index of this proof for the submitting user (0 if not submitted)
    function getProofData(bytes32 proofHash)
        external
        view
        returns (bool submitted, uint128 timestamp, uint128 userIndex)
    {
        ProofData memory data = proofData[proofHash];
        return (data.submitted, data.timestamp, data.userIndex);
    }

    /// @notice Get the number of proofs submitted by a user
    /// @param user The address to query
    /// @return The number of proofs submitted by the user
    function getUserProofCount(address user) external view returns (uint256) {
        return uint256(userProofCount[user]);
    }
}

    function transferOwnership(address newOwner) external {
        if (msg.sender != owner) revert Unauthorized();
        owner = newOwner;
    }

    function setVerifier(address _verifier) external {
        if (msg.sender != owner) revert Unauthorized();
        verifier = _verifier;
    }

    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256(bytes("BaseProof")), keccak256(bytes("1")), block.chainid, address(this)));
    }

    function _verifySignature(bytes32 digest, uint8 v, bytes32 r, bytes32 s) internal view {
        address recovered = ecrecover(digest, v, r, s);
        if (recovered == address(0) || recovered != verifier) revert InvalidSignature();
    }
}
