// SPDX-License-Identifier: AGPL-3.0-or-later

pragma solidity ^0.8.19;

import "./IKeyRegistry.sol";

contract KeyRegistry is IKeyRegistry {
    type KeyId is bytes32;

    struct Certification {
        CertId id;
        uint256 validBefore;
        bytes publicKey;
        bytes location;
    }

    mapping(KeyId => Certification) private _keys;

    function _keyId(address addr, bytes12 kind) private pure returns (KeyId) {
        return KeyId.wrap(bytes32(abi.encodePacked(addr, kind)));
    }

    function _certId(bytes12 kind, uint256 validBefore, bytes memory publicKey)
        private
        pure
        returns (CertId)
    {
        bytes32 digest = keccak256(abi.encode(validBefore, publicKey));
        digest &= ~bytes32(hex"FFFFFFFFFFFFFFFFFFFFFFFF");

        return CertId.wrap(uint256(bytes32(kind) | digest));
    }

    function _cert(address addr, bytes12 kind)
        private
        view
        returns (Certification storage)
    {
        Certification storage cert = _keys[_keyId(addr, kind)];
        require(0 != CertId.unwrap(cert.id));
        require(block.timestamp < cert.validBefore);
        return cert;
    }

    //--------------------------------------------------------------------------
    // Key Management Functions
    //--------------------------------------------------------------------------

    /// @notice Link the given key with the sender's (certifier's) address.
    function _certify(
        address msgSender,
        bytes12 kind,
        uint256 validBefore,
        bytes calldata publicKey,
        bytes calldata location
    ) private returns (CertId) {
        require(0 < publicKey.length);
        require(block.timestamp < validBefore);

        Certification storage current = _keys[_keyId(msgSender, kind)];

        CertId newId = _certId(kind, validBefore, publicKey);
        CertId oldId = current.id;

        if (CertId.unwrap(newId) != CertId.unwrap(oldId)) {
            if (0 < current.publicKey.length) {
                emit Revoke(msgSender, kind, oldId);
            }

            current.validBefore = validBefore;
            current.publicKey = publicKey;
            current.id = newId;
        }

        current.location = location;

        emit Certify(msgSender, kind, newId);

        return newId;
    }

    function certify(
        bytes12 kind,
        uint256 validBefore,
        bytes calldata publicKey,
        bytes calldata location
    ) external returns (CertId) {
        return _certify(msg.sender, kind, validBefore, publicKey, location);
    }

    /// @notice Mark the identified key as revoked.
    function revoke(CertId certId) external {
        require(CertId.unwrap(certId) != 0);

        uint256 unwrap = CertId.unwrap(certId);

        bytes12 kind = bytes12(bytes32(unwrap));
        KeyId kid = _keyId(msg.sender, kind);

        require(CertId.unwrap(_keys[kid].id) == unwrap);

        _keys[kid] = Certification({
            id: CertId.wrap(0),
            validBefore: 0,
            publicKey: hex"",
            location: hex""
        });

        emit Revoke(msg.sender, kind, certId);
    }

    //--------------------------------------------------------------------------
    // Getter Functions
    //--------------------------------------------------------------------------

    /// @notice Retrieve the revocation token for a certification.
    function idOf(address addr, bytes12 kind) external view returns (CertId) {
        return _cert(addr, kind).id;
    }

    /// @notice Retrieve the public key of a certification.
    function keyOf(address addr, bytes12 kind)
        external
        view
        returns (bytes memory publicKey)
    {
        return _cert(addr, kind).publicKey;
    }

    /// @notice Retrieve the location of data associated with a certification.
    function locationOf(address addr, bytes12 kind)
        external
        view
        returns (bytes memory location)
    {
        return _cert(addr, kind).location;
    }

    /// @notice Retrieve the first second where the certification is invalid.
    function validBeforeOf(address addr, bytes12 kind)
        external
        view
        returns (uint256 validBefore)
    {
        return _cert(addr, kind).validBefore;
    }

    //--------------------------------------------------------------------------
    // Permit-style Functions
    //--------------------------------------------------------------------------

    /// @notice Mark the identified key as revoked.
    function revoke(CertId, /* certId */ bytes calldata /* signature */ )
        external
        pure
    {
        revert("TODO");
    }

    /// @notice Link the key with the address recovered from the signature.
    function certify(
        bytes12, /* kind */
        uint256, /* validBefore */
        bytes calldata, /* publicKey */
        bytes calldata, /* location */
        uint256, /* signatureValidBefore */
        bytes calldata /* signature */
    ) external pure returns (CertId) {
        revert("TODO");
    }

    //--------------------------------------------------------------------------
    // Multi-call Functions
    //--------------------------------------------------------------------------

    /// @dev See https://eips.ethereum.org/EIPS/eip-6357.
    function multicall(bytes[] calldata data)
        external
        returns (bytes[] memory results)
    {
        results = new bytes[](data.length);
        for (uint256 i = 0; i < data.length; i++) {
            (bool success, bytes memory returndata) =
                address(this).delegatecall(data[i]);
            require(success);
            results[i] = returndata;
        }
        return results;
    }
}
