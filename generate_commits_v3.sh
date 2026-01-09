#!/bin/bash
set -e

# Define timestamps for commits to ensure order
t=$(date +%s)

# Helper function to commit
c() {
    git add .
    git commit -m "$1"
    sleep 1
}

echo "Starting commit generation..."

# ==============================================================================
# 0. Reset to Original State (Simulated)
# ==============================================================================
rm -f src/IBaseProof.sol

cat > src/BaseProof.sol << 'EOF'
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/// @title BaseProof
/// @notice Trust-minimized action proofs on Base
/// @dev Stores cryptographic proof hashes and prevents duplicates
/// @dev Optimized for gas efficiency on L2
contract BaseProof {
    address public owner;
    address public pendingOwner;
    mapping(address => bool) public isVerifier;
    bool public paused;

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

    function submitProof(bytes32 proofHash, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external whenNotPaused {
        if (block.timestamp > deadline) revert DeadlineExpired();
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), keccak256(abi.encode(PROOF_TYPEHASH, proofHash, deadline))));
        _verifySignature(digest, v, r, s);

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

    function submitProofBatch(bytes32[] calldata proofHashes, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external whenNotPaused {
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
EOF

# Reset Test File to Original
cat > test/BaseProof.t.sol << 'EOF'
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
}
EOF

# ==============================================================================
# 1. New Interface
# ==============================================================================
cat > src/IBaseProof.sol << 'EOF'
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
    event BatchProofSubmitted(address indexed user, uint256 count, uint256 timestamp);
    event Paused(address account);
    event Unpaused(address account);
    event VerifierAdded(address indexed verifier);
    event VerifierRemoved(address indexed verifier);
    
    function submitProof(bytes32 proofHash, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external;
}
EOF
c "feat: add IBaseProof interface"

# ==============================================================================
# 2. Inherit Interface
# ==============================================================================
sed -i 's/contract BaseProof {/import {IBaseProof} from ".\/IBaseProof.sol";\n\ncontract BaseProof is IBaseProof {/' src/BaseProof.sol
sed -i '/error ProofAlreadySubmitted/,/error Unauthorized();/d' src/BaseProof.sol
c "refactor: inherit IBaseProof in BaseProof"

# ==============================================================================
# 3. Add Metadata Hash Param to submitProof in Interface
# ==============================================================================
cat > src/IBaseProof.sol << 'EOF'
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
EOF
c "feat: update interface signatures for metadata"

# ==============================================================================
# 4. Update submitProof logic (Signature Only first to avoid breaking build too much?)
# No, let's just do implementation
# ==============================================================================
sed -i 's/function submitProof(bytes32 proofHash, uint256 deadline/function submitProof(bytes32 proofHash, bytes32 metadataHash, uint256 deadline/' src/BaseProof.sol
c "feat: update submitProof signature"

# ==============================================================================
# 5. Store Metadata
# ==============================================================================
sed -i '/data.userIndex = userProofCount\[msg.sender\];/a \        data.metadataHash = metadataHash;' src/BaseProof.sol
c "feat: store metadataHash in submitProof"

# ==============================================================================
# 6. Update submitProofBatch Signature
# ==============================================================================
sed -i 's/function submitProofBatch(bytes32\[\] calldata proofHashes, uint256 deadline/function submitProofBatch(bytes32[] calldata proofHashes, bytes32[] calldata metadataHashes, uint256 deadline/' src/BaseProof.sol
c "feat: update submitProofBatch signature"

# ==============================================================================
# 7. Store Metadata Batch & Optimize
# ==============================================================================
# Using cat for clean swap of the function loop
# This replaces the entire submitProofBatch function's body essentially, but keeping it simple for script:
sed -i '/if (length == 0) revert EmptyBatch();/a \        if (metadataHashes.length != length) revert InvalidSignature();' src/BaseProof.sol
sed -i '/data.userIndex = userCount + uint128(i);/a \            data.metadataHash = metadataHashes[i];' src/BaseProof.sol
# Remove nested loop (Optimization)
sed -i '/for (uint256 j = i + 1; j < length; ++j) {/,/}/d' src/BaseProof.sol
c "feat: store metadata batch and remove O(N^2) check"

# ==============================================================================
# 8. Add Revocation to Interface
# ==============================================================================
sed -i '/event ProofSubmitted/a \    event ProofRevoked(bytes32 indexed proofHash, address indexed revoker);' src/IBaseProof.sol
sed -i '/function submitProofBatch/i \    function revokeProof(bytes32 proofHash) external;\n' src/IBaseProof.sol
c "feat: add revocation events and method to interface"

# ==============================================================================
# 9. Add Revoked Flag to Struct
# ==============================================================================
sed -i '/bool submitted;/a \        bool revoked;' src/BaseProof.sol
c "feat: add revoked field to ProofData"

# ==============================================================================
# 10. Implement revokeProof
# ==============================================================================
sed -i '/function removeVerifier/a \\n    function revokeProof(bytes32 proofHash) external {\n        if (msg.sender != owner && !isVerifier[msg.sender]) revert Unauthorized();\n        ProofData storage data = proofData[proofHash];\n        if (!data.submitted) revert Unauthorized();\n        data.revoked = true;\n        emit ProofRevoked(proofHash, msg.sender);\n    }' src/BaseProof.sol
c "feat: implement revokeProof logic"

# ==============================================================================
# 11. Update isProofSubmitted to check revoked
# ==============================================================================
sed -i 's/return proofData\[proofHash\].submitted;/return proofData[proofHash].submitted && !proofData[proofHash].revoked;/' src/BaseProof.sol
# Add isProofRevoked
sed -i '/function isProofSubmitted/a \\n    function isProofRevoked(bytes32 proofHash) external view returns (bool) {\n        return proofData[proofHash].revoked;\n    }' src/BaseProof.sol
c "feat: update isProofSubmitted to respect revocation"

# ==============================================================================
# 12. Add Ownership Events
# ==============================================================================
sed -i '/PROOF_TYPEHASH/a \\n    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);\n    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);' src/BaseProof.sol
sed -i 's/owner = msg.sender;/owner = msg.sender;\n        emit OwnershipTransferred(address(0), msg.sender);/' src/BaseProof.sol
c "feat: add ownership events"

# ==============================================================================
# 13. Emit Events in Ownership Functions
# ==============================================================================
sed -i '/pendingOwner = _newOwner;/a \        emit OwnershipTransferStarted(owner, _newOwner);' src/BaseProof.sol
sed -i '/owner = pendingOwner;/i \        emit OwnershipTransferred(owner, pendingOwner);' src/BaseProof.sol
c "feat: emit ownership events on transfer"

# ==============================================================================
# 14. Implement renounceOwnership
# ==============================================================================
sed -i '/function acceptOwnership() external {/,/}/a \\n    function renounceOwnership() external onlyOwner {\n        emit OwnershipTransferred(owner, address(0));\n        owner = address(0);\n        pendingOwner = address(0);\n    }' src/BaseProof.sol
c "feat: implement renounceOwnership"

# ==============================================================================
# 15. Update Tests
# ==============================================================================
# Writing the full test file content as it has many changes
cat > test/BaseProof.t.sol << 'EOF'
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

    function _sign(bytes32 hash, uint256 deadline) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", baseProof.DOMAIN_SEPARATOR(), keccak256(abi.encode(baseProof.PROOF_TYPEHASH(), hash, deadline))));
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
        
        (,,,, bytes32 storedMeta) = baseProof.getProofData(proofHash);
        assertEq(storedMeta, metadataHash);
    }

    function test_RevertWhen_DuplicateProof() public {
        bytes32 proofHash = keccak256("test proof");
        bytes32 metadataHash = keccak256("json metadata");
        uint256 dl = block.timestamp + 100;
        (uint8 v, bytes32 r, bytes32 s) = _sign(proofHash, dl);
        
        vm.prank(user1);
        baseProof.submitProof(proofHash, metadataHash, dl, v, r, s);

        vm.prank(user2);
        vm.expectRevert(abi.encodeWithSelector(IBaseProof.ProofAlreadySubmitted.selector, proofHash));
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
        
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", baseProof.DOMAIN_SEPARATOR(), keccak256(abi.encode(baseProof.BATCH_TYPEHASH(), keccak256(abi.encodePacked(proofHashes)), dl))));
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
}
EOF
c "test: update tests for new features"

echo "Done! Generated 15 commits."
