// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract EvidentiaAnchor {
    struct AnchorData {
        string cid;
        uint256 timestamp;
    }

    mapping(bytes32 => AnchorData) public anchors;

    event AnchorSubmitted(bytes32 indexed merkleRoot, string cid, uint256 timestamp);

    function submitAnchor(bytes32 merkleRoot, string calldata cid) external {
        anchors[merkleRoot] = AnchorData({
            cid: cid,
            timestamp: block.timestamp
        });
        emit AnchorSubmitted(merkleRoot, cid, block.timestamp);
    }

    function submitAnchors(bytes32[] calldata merkleRoots, string[] calldata cids) external {
        require(merkleRoots.length == cids.length, "Length mismatch");
        for (uint256 i = 0; i < merkleRoots.length; i++) {
            anchors[merkleRoots[i]] = AnchorData({
                cid: cids[i],
                timestamp: block.timestamp
            });
            emit AnchorSubmitted(merkleRoots[i], cids[i], block.timestamp);
        }
    }

    function verifyProof(
        bytes32 merkleRoot,
        bytes32 leaf,
        bytes32[] calldata proof
    ) external view returns (bool) {
        if (anchors[merkleRoot].timestamp == 0) {
            return false;
        }

        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];
            if (computedHash <= proofElement) {
                computedHash = keccak256(abi.encodePacked(computedHash, proofElement));
            } else {
                computedHash = keccak256(abi.encodePacked(proofElement, computedHash));
            }
        }

        return computedHash == merkleRoot;
    }
}
