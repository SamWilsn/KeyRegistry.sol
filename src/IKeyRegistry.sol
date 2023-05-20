// SPDX-License-Identifier: CC0-1.0

pragma solidity ^0.8.19;

type CertId is uint256;

using {certIdEq as ==} for CertId global;

function certIdEq(CertId a, CertId b) pure returns (bool) {
    return CertId.unwrap(a) == CertId.unwrap(b);
}

interface IKeyRegistry {
    //--------------------------------------------------------------------------
    // Events
    //--------------------------------------------------------------------------

    event Certify(
        address indexed certifier, bytes12 indexed kind, CertId indexed certId
    );

    event Revoke(
        address indexed certifier, bytes12 indexed kind, CertId indexed certId
    );

    //--------------------------------------------------------------------------
    // Key Management Functions
    //--------------------------------------------------------------------------

    /// @notice Link the given key with the sender's (certifier's) address.
    function certify(
        bytes12 kind,
        uint256 validBefore,
        bytes memory publicKey,
        bytes memory location
    ) external returns (CertId);

    /// @notice Mark the identified key as revoked.
    function revoke(CertId certId) external;

    //--------------------------------------------------------------------------
    // Getter Functions
    //--------------------------------------------------------------------------

    /// @notice Retrieve the revocation token for a certification.
    function idOf(address addr, bytes12 kind) external view returns (CertId);

    /// @notice Retrieve the public key of a certification.
    function keyOf(address addr, bytes12 kind)
        external
        view
        returns (bytes memory publicKey);

    /// @notice Retrieve the location of data associated with a certification.
    function locationOf(address addr, bytes12 kind)
        external
        view
        returns (bytes memory location);

    /// @notice Retrieve the first second where the certification is invalid.
    function validBeforeOf(address addr, bytes12 kind)
        external
        view
        returns (uint256 validBefore);

    //--------------------------------------------------------------------------
    // Permit-style Functions
    //--------------------------------------------------------------------------

    /// @notice Mark the identified key as revoked.
    function revoke(CertId certId, bytes calldata signature) external;

    /// @notice Link the key with the address recovered from the signature.
    function certify(
        bytes12 kind,
        uint256 validBefore,
        bytes calldata publicKey,
        bytes calldata location,
        uint256 signatureValidBefore,
        bytes calldata signature
    ) external returns (CertId);

    //--------------------------------------------------------------------------
    // Multi-call Functions
    //--------------------------------------------------------------------------

    /// @dev See https://eips.ethereum.org/EIPS/eip-6357.
    function multicall(bytes[] calldata data)
        external
        returns (bytes[] memory);
}
