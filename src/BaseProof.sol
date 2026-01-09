// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/// @title BaseProof
/// @notice Trust-minimized action proofs on Base
/// @dev Stores cryptographic proof hashes and prevents duplicates
/// @dev Optimized for gas efficiency on L2
import {IBaseProof} from "./IBaseProof.sol";

contract BaseProof is IBaseProof {
    address public owner;
    address public pendingOwner;
    mapping(address => bool) public isVerifier;
    bool public paused;

    bytes32 public constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 public constant PROOF_TYPEHASH = keccak256("Proof(bytes32 proofHash,uint256 deadline)");
    bytes32 public constant BATCH_TYPEHASH = keccak256("BatchProof(bytes32[] proofHashes,uint256 deadline)");

    /// @notice Custom error for duplicate proof submission

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

    event Paused(address account);
    event Unpaused(address account);
    event VerifierAdded(address indexed verifier);
    event VerifierRemoved(address indexed verifier);

    struct ProofData {
        bool submitted;
        uint128 timestamp;
        uint128 userIndex;
        bytes32 metadataHash;
    }

    mapping(bytes32 => ProofData) public proofData;
    mapping(address => uint128) public userProofCount;
    uint128 public totalProofs;

    constructor(address _verifier) {
        owner = msg.sender;
        isVerifier[_verifier] = true;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    modifier whenNotPaused() {
        if (paused) revert Unauthorized();
        _;
    }

    function togglePause() external onlyOwner {
        paused = !paused;
        if (paused) emit Paused(msg.sender);
        else emit Unpaused(msg.sender);
    }

    function transferOwnership(address _newOwner) external onlyOwner {
        pendingOwner = _newOwner;
    }

    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert Unauthorized();
        owner = pendingOwner;
        pendingOwner = address(0);
    }

    function addVerifier(address _verifier) external onlyOwner {
        isVerifier[_verifier] = true;
        emit VerifierAdded(_verifier);
    }

    function removeVerifier(address _verifier) external onlyOwner {
        isVerifier[_verifier] = false;
        emit VerifierRemoved(_verifier);
    }

    function submitProof(bytes32 proofHash, bytes32 metadataHash, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external whenNotPaused {
        if (block.timestamp > deadline) revert DeadlineExpired();
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), keccak256(abi.encode(PROOF_TYPEHASH, proofHash, deadline))));
        _verifySignature(digest, v, r, s);

        ProofData storage data = proofData[proofHash];
        if (data.submitted) revert ProofAlreadySubmitted(proofHash);

        data.submitted = true;
        uint256 currentTimestamp = block.timestamp;
        data.timestamp = uint128(currentTimestamp);
        data.userIndex = userProofCount[msg.sender];
        data.metadataHash = metadataHash;
        
        userProofCount[msg.sender]++;
        totalProofs++;

        emit ProofSubmitted(msg.sender, proofHash, currentTimestamp);
    }

    function submitProofBatch(bytes32[] calldata proofHashes, bytes32[] calldata metadataHashes, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external whenNotPaused {
        if (block.timestamp > deadline) revert DeadlineExpired();
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), keccak256(abi.encode(BATCH_TYPEHASH, keccak256(abi.encodePacked(proofHashes)), deadline))));
        _verifySignature(digest, v, r, s);

        uint256 length = proofHashes.length;
        if (length == 0) revert EmptyBatch();

        uint256 timestamp = block.timestamp;
        uint128 userCount = userProofCount[msg.sender];

        for (uint256 i = 0; i < length; ++i) {
            bytes32 proofHash = proofHashes[i];
            ProofData storage data = proofData[proofHash];
            
            if (data.submitted) revert ProofAlreadySubmitted(proofHash);
            
            for (uint256 j = i + 1; j < length; ++j) {
                if (proofHash == proofHashes[j]) revert DuplicateInBatch(j);
            }

            data.submitted = true;
            data.timestamp = uint128(timestamp);
            data.userIndex = userCount + uint128(i);
        }

        userProofCount[msg.sender] += uint128(length);
        totalProofs += uint128(length);

        emit BatchProofSubmitted(msg.sender, length, timestamp);
    }

    function isProofSubmitted(bytes32 proofHash) external view returns (bool) {
        return proofData[proofHash].submitted;
    }

    function getProofData(bytes32 proofHash) external view returns (bool submitted, uint128 timestamp, uint128 userIndex) {
        ProofData memory data = proofData[proofHash];
        return (data.submitted, data.timestamp, data.userIndex);
    }

    function getProofMetadata(bytes32 proofHash) external view returns (bytes32) {
        return proofData[proofHash].metadataHash;
    }

    function getUserProofCount(address user) external view returns (uint256) {
        return uint256(userProofCount[user]);
    }

    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256(bytes("BaseProof")), keccak256(bytes("1")), block.chainid, address(this)));
    }

    function _verifySignature(bytes32 digest, uint8 v, bytes32 r, bytes32 s) internal view {
        address recoveredSigner = ecrecover(digest, v, r, s);
        if (recoveredSigner == address(0) || !isVerifier[recoveredSigner]) revert InvalidSignature();
    }
}
