// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.19;

import {VmSafe} from "forge-std/Vm.sol";
import "forge-std/Test.sol";
import "../src/KeyRegistry.sol";

contract KeyRegistryTest is Test {
    event Certify(
        address indexed certifier, bytes12 indexed kind, CertId indexed certId
    );

    event Revoke(
        address indexed certifier, bytes12 indexed kind, CertId indexed certId
    );

    KeyRegistry public registry;

    function setUp() public {
        registry = new KeyRegistry();
    }

    function testCertify_New_EmitsCertifyLog() public {
        // Ensure the correct log is emitted.
        vm.expectEmit(true, true, true, true);
        emit Certify(
            address(this),
            hex"112233445566778899aabbcc",
            CertId.wrap(
                0x112233445566778899aabbcc907c569576533b61f7607eab4698868850fac4dc
            )
        );

        CertId id = registry.certify(
            hex"112233445566778899aabbcc", ~uint64(0), hex"ff", hex"ff"
        );

        assertEq(
            CertId.unwrap(id),
            0x112233445566778899aabbcc907c569576533b61f7607eab4698868850fac4dc
        );
    }

    function testCertify_ChangeValidBefore_EmitsRevokeAndCertifyLogs() public {
        CertId revokeId = registry.certify(
            hex"112233445566778899aabbcc", ~uint64(1), hex"ff", hex"ff"
        );

        // Ensure the correct revoke log is emitted.
        vm.expectEmit(true, true, true, true);
        emit Revoke(address(this), hex"112233445566778899aabbcc", revokeId);

        // Then expect the correct certify log.
        vm.expectEmit(true, true, true, true);
        emit Certify(
            address(this),
            hex"112233445566778899aabbcc",
            CertId.wrap(
                0x112233445566778899aabbcc907c569576533b61f7607eab4698868850fac4dc
            )
        );

        CertId id = registry.certify(
            hex"112233445566778899aabbcc", ~uint64(0), hex"ff", hex"ff"
        );

        assertEq(
            CertId.unwrap(id),
            0x112233445566778899aabbcc907c569576533b61f7607eab4698868850fac4dc
        );
    }

    function testCertify_ChangePublicKey_EmitsRevokeAndCertifyLogs() public {
        CertId revokeId = registry.certify(
            hex"112233445566778899aabbcc", ~uint64(0), hex"fe", hex"ff"
        );

        // Ensure the correct revoke log is emitted.
        vm.expectEmit(true, true, true, true);
        emit Revoke(address(this), hex"112233445566778899aabbcc", revokeId);

        // Then expect the correct certify log.
        vm.expectEmit(true, true, true, true);
        emit Certify(
            address(this),
            hex"112233445566778899aabbcc",
            CertId.wrap(
                0x112233445566778899aabbcc907c569576533b61f7607eab4698868850fac4dc
            )
        );

        CertId id = registry.certify(
            hex"112233445566778899aabbcc", ~uint64(0), hex"ff", hex"ff"
        );

        assertEq(
            CertId.unwrap(id),
            0x112233445566778899aabbcc907c569576533b61f7607eab4698868850fac4dc
        );
    }

    function testCertify_ChangeLocation_EmitsOnlyCertifyLog() public {
        // Certify some public key.
        CertId initialId = registry.certify(
            hex"112233445566778899aabbcc", ~uint64(0), hex"ff", hex"fe"
        );

        // Then expect the correct certify log.
        vm.expectEmit(true, true, true, true);
        emit Certify(address(this), hex"112233445566778899aabbcc", initialId);

        // Re-certify the same key with a different location.
        vm.recordLogs();
        CertId id = registry.certify(
            hex"112233445566778899aabbcc", ~uint64(0), hex"ff", hex"ff"
        );
        VmSafe.Log[] memory recorded = vm.getRecordedLogs();

        assertEq(CertId.unwrap(id), CertId.unwrap(initialId));
        assertEq(1, recorded.length);
    }

    function testRevoke_NeverCreated0() public {
        // Revoke the certificate.
        try registry.revoke(CertId.wrap(0)) {
            fail("Expected revert, but didn't");
        } catch {
            // Task failed successfully.
        }
    }

    function testRevoke_NeverCreated() public {
        // Revoke the certificate.
        try registry.revoke(CertId.wrap(1)) {
            fail("Expected revert, but didn't");
        } catch {
            // Task failed successfully.
        }
    }

    function testRevoke_Exists() public {
        // Certify some public key.
        CertId id = registry.certify(
            hex"112233445566778899aabbcc", ~uint64(0), hex"ff", hex"fe"
        );

        // Then expect the correct revoke log.
        vm.expectEmit(true, true, true, true);
        emit Revoke(address(this), hex"112233445566778899aabbcc", id);

        // Revoke the certificate.
        registry.revoke(id);
    }

    function testIdOf_Revoked() public {
        CertId revokeId = registry.certify(
            hex"112233445566778899aabbcc", ~uint256(0), hex"ff", hex"ff"
        );

        registry.revoke(revokeId);

        try registry.idOf(address(this), hex"112233445566778899aabbcc") {
            fail("Expected revert.");
        } catch {
            // Task failed successfully.
        }
    }

    function testIdOf_Expired() public {
        registry.certify(
            hex"112233445566778899aabbcc", block.timestamp + 1, hex"ff", hex"ff"
        );

        vm.warp(block.timestamp + 1);

        try registry.idOf(address(this), hex"112233445566778899aabbcc") {
            fail("Expected revert.");
        } catch {
            // Task failed successfully.
        }
    }

    function testIdOf_NeverCreated() public {
        try registry.idOf(address(this), hex"ffffffffffffffffffffffff") {
            fail("Expected revert.");
        } catch {
            // Task failed successfully.
        }
    }

    function testIdOf_Exists() public {
        registry.certify(
            hex"112233445566778899aabbcc", ~uint64(0), hex"ff", hex"ff"
        );

        CertId actual =
            registry.idOf(address(this), hex"112233445566778899aabbcc");

        assertEq(
            CertId.unwrap(actual),
            0x112233445566778899aabbcc907c569576533b61f7607eab4698868850fac4dc
        );
    }
}
