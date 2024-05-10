// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";
import "forge-std/console2.sol";

import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import {UserOperation} from "@eth-infinitism/account-abstraction/interfaces/UserOperation.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {UpgradeableModularAccount} from "@erc6900/reference-implementation/account/UpgradeableModularAccount.sol";
import {Execution} from "@erc6900/reference-implementation/libraries/ERC6900TypeUtils.sol";

import {AccessControlPlugin} from "contracts/src/AccessControlPlugin.sol";
import {IAccessControlPlugin} from "contracts/src/interfaces/IAccessControlPlugin.sol";
import "./mocks/ContractOwner.sol";
import "./mocks/Callee.sol";
import "./mocks/MSCAFactoryFixture.sol";

contract AccessControlPluginTest is Test {
    using ECDSA for bytes32;

    AccessControlPlugin public plugin;
    EntryPoint public entryPoint;
    ContractOwner public contractOwner;
    Callee public callee;
    MSCAFactoryFixture public factory;

    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;
    bytes32 public constant SIGNER_ROLE = keccak256("SIGNER_ROLE");

    bytes4 internal constant _1271_MAGIC_VALUE = 0x1626ba7e;
    bytes4 internal constant _1271_INVALID_SIG = 0xFFFFFFFF;
    address public a;
    address public b;

    address public admin1;
    address public admin2;

    enum FunctionId {
        RUNTIME_VALIDATION_ADMIN_OR_SELF,
        RUNTIME_VALIDATION_SIGNER_OR_SELF,
        USER_OP_VALIDATION_ADMIN,
        USER_OP_VALIDATION_SIGNER
    }

    function setUp() public {
        entryPoint = new EntryPoint();
        contractOwner = new ContractOwner();
        callee = new Callee();
        factory = new MSCAFactoryFixture(entryPoint);
        plugin = AccessControlPlugin(address(factory.accessControlPlugin()));

        a = makeAddr("a");
        b = makeAddr("b");
        admin1 = makeAddr("admin1");
        admin2 = makeAddr("admin2");
    }

    function test_UninitializedAdmin() public {
        assertFalse(plugin.hasRole(DEFAULT_ADMIN_ROLE, admin1));
    }

    function test_InitializedAdmin() public {
        plugin.grantRole(DEFAULT_ADMIN_ROLE, admin1);
        assertTrue(plugin.hasRole(DEFAULT_ADMIN_ROLE, admin1));
    }

    function test_AdminForSender() public {
        vm.startPrank(a);
        assertFalse(plugin.hasRole(DEFAULT_ADMIN_ROLE, admin1));
        plugin.grantRole(DEFAULT_ADMIN_ROLE, admin1);
        assertTrue(plugin.hasRole(DEFAULT_ADMIN_ROLE, admin1));

        vm.startPrank(b);
        assertFalse(plugin.hasRole(DEFAULT_ADMIN_ROLE, admin1));
        assertFalse(plugin.hasRole(DEFAULT_ADMIN_ROLE, admin2));
        plugin.grantRole(DEFAULT_ADMIN_ROLE, admin2);
        assertTrue(plugin.hasRole(DEFAULT_ADMIN_ROLE, admin2));
    }

    function testFuzz_ValidateRuntimeValidationForAdmin() public {
        vm.startPrank(a);
        assertFalse(plugin.hasRole(DEFAULT_ADMIN_ROLE, admin1));
        plugin.grantRole(DEFAULT_ADMIN_ROLE, admin1);
        assertTrue(plugin.hasRole(DEFAULT_ADMIN_ROLE, admin1));

        plugin.runtimeValidationFunction(
            uint8(IAccessControlPlugin.FunctionId.RUNTIME_VALIDATION_ADMIN_OR_SELF), admin1, 0, ""
        );

        vm.startPrank(b);
        vm.expectRevert(IAccessControlPlugin.NotAuthorized.selector);
        plugin.runtimeValidationFunction(
            uint8(IAccessControlPlugin.FunctionId.RUNTIME_VALIDATION_ADMIN_OR_SELF), admin1, 0, ""
        );
    }

    function testFuzz_ValidateRuntimeValidationForSigner(address signer) public {
        vm.assume(a != signer);
        vm.startPrank(a);
        // Should fail
        vm.expectRevert(IAccessControlPlugin.NotAuthorized.selector);
        plugin.runtimeValidationFunction(
            uint8(IAccessControlPlugin.FunctionId.RUNTIME_VALIDATION_SIGNER_OR_SELF), signer, 0, ""
        );

        assertFalse(plugin.hasRole(SIGNER_ROLE, signer));
        plugin.grantRole(SIGNER_ROLE, signer);
        assertTrue(plugin.hasRole(SIGNER_ROLE, signer));

        // Should fail
        vm.expectRevert(IAccessControlPlugin.NotAuthorized.selector);
        plugin.runtimeValidationFunction(
            uint8(IAccessControlPlugin.FunctionId.RUNTIME_VALIDATION_SIGNER_OR_SELF), signer, 0, ""
        );

        plugin.setRolePermitAll(SIGNER_ROLE, true);

        // Should pass
        plugin.runtimeValidationFunction(
            uint8(IAccessControlPlugin.FunctionId.RUNTIME_VALIDATION_SIGNER_OR_SELF), signer, 0, ""
        );

        vm.startPrank(b);
        vm.expectRevert(IAccessControlPlugin.NotAuthorized.selector);
        plugin.runtimeValidationFunction(
            uint8(IAccessControlPlugin.FunctionId.RUNTIME_VALIDATION_SIGNER_OR_SELF), signer, 0, ""
        );
    }

    function testFuzz_ValidateUserOpSigForAdmin(string memory salt, UserOperation memory userOp) public {        
        // range bound the possible set of priv keys
        (address signer, uint256 privateKey) = makeAddrAndKey(salt);

        vm.startPrank(a);
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, userOpHash.toEthSignedMessageHash());

        // sig cannot cover the whole userop struct since userop struct has sig field
        userOp.signature = abi.encodePacked(r, s, v);

        // sig check should fail
        uint256 failed = plugin.userOpValidationFunction(
            uint8(IAccessControlPlugin.FunctionId.USER_OP_VALIDATION_ADMIN), userOp, userOpHash
        );
        assertEq(failed, 1);

        // grant admin to signer
        plugin.grantRole(DEFAULT_ADMIN_ROLE, signer);
        assertTrue(plugin.hasRole(DEFAULT_ADMIN_ROLE, signer));

        // sig check should pass
        failed = plugin.userOpValidationFunction(
            uint8(IAccessControlPlugin.FunctionId.USER_OP_VALIDATION_ADMIN), userOp, userOpHash
        );
        assertEq(failed, 0);
    }

    function testFuzz_ValidateUserOpSigForSigner(string memory salt, UserOperation memory userOp) public {
        // range bound the possible set of priv keys
        (address signer, uint256 privateKey) = makeAddrAndKey(salt);
        vm.assume(signer != admin1);

        vm.startPrank(a);
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, userOpHash.toEthSignedMessageHash());

        // sig cannot cover the whole userop struct since userop struct has sig field
        userOp.signature = abi.encodePacked(r, s, v);

        // sig check should fail
        uint256 failed = plugin.userOpValidationFunction(
            uint8(IAccessControlPlugin.FunctionId.USER_OP_VALIDATION_SIGNER), userOp, userOpHash
        );
        assertEq(failed, 1);

        // grant admin to admin1
        plugin.grantRole(DEFAULT_ADMIN_ROLE, admin1);
        assertTrue(plugin.hasRole(DEFAULT_ADMIN_ROLE, admin1));

        // grant signer to signer
        plugin.grantRole(SIGNER_ROLE, signer);
        assertTrue(plugin.hasRole(SIGNER_ROLE, signer));

        // sig check should fail
        failed = plugin.userOpValidationFunction(
            uint8(IAccessControlPlugin.FunctionId.USER_OP_VALIDATION_SIGNER), userOp, userOpHash
        );
        assertEq(failed, 1);

        // set permitAll
        plugin.setRolePermitAll(SIGNER_ROLE, true);

        // sig check should pass
        failed = plugin.userOpValidationFunction(
            uint8(IAccessControlPlugin.FunctionId.USER_OP_VALIDATION_SIGNER), userOp, userOpHash
        );
        assertEq(failed, 0);
    }

    function testFuzz_IsValidSignatureForEOAOwner(string memory salt, bytes32 digest) public {
        // range bound the possible set of priv keys
        (address signer, uint256 privateKey) = makeAddrAndKey(salt);

        vm.startPrank(a);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);

        // sig check should fail
        assertEq(plugin.isValidSignature(digest, abi.encodePacked(r, s, v)), _1271_INVALID_SIG);

        // transfer admin to signer
        plugin.grantRole(DEFAULT_ADMIN_ROLE, signer);
        assertTrue(plugin.hasRole(DEFAULT_ADMIN_ROLE, signer));

        // sig check should pass
        assertEq(plugin.isValidSignature(digest, abi.encodePacked(r, s, v)), _1271_MAGIC_VALUE);
    }

    function testFuzz_IsValidSignatureForContractOwner(bytes32 digest) public {
        vm.startPrank(a);
        plugin.grantRole(DEFAULT_ADMIN_ROLE, address(contractOwner));
        assertTrue(plugin.hasRole(DEFAULT_ADMIN_ROLE, address(contractOwner)));
        bytes memory signature = contractOwner.sign(digest);
        assertEq(plugin.isValidSignature(digest, signature), _1271_MAGIC_VALUE);
    }

    /// Permissions check

    function test_PermissionsCheckForAdmin(address admin, uint salt) public {
        UpgradeableModularAccount account = factory.createAccountWithAccessControl(admin, salt);
        AccessControlPlugin _plugin = AccessControlPlugin(address(account));

        assertTrue(_plugin.hasRole(DEFAULT_ADMIN_ROLE, admin));

        vm.startPrank(admin);
        console2.log("admin:", admin);

        uint snapshotId = vm.snapshot();

        _plugin.grantRole(SIGNER_ROLE, address(1));
        assertTrue(_plugin.hasRole(SIGNER_ROLE, address(1)));

        _plugin.setRolePermitAll(SIGNER_ROLE, true);
        _plugin.setRoleAccess(SIGNER_ROLE, address(1), bytes4(0x12345678), true);
        IAccessControlPlugin.Access[] memory accesses = new IAccessControlPlugin.Access[](1);
        accesses[0] = IAccessControlPlugin.Access(address(2), bytes4(0x12345678), true);
        _plugin.setRoleAccessBatch(SIGNER_ROLE, accesses);

        _plugin.setRoleStopped(SIGNER_ROLE, true);

        account.execute(Execution({
            target: address(callee),
            value: 0,
            data: abi.encode(bytes4(0x12345678))
        }));

        assertEq(callee.lastSender(), address(account));
        assertEq(callee.lastCalldata(), abi.encode(bytes4(0x12345678)));

        vm.revertTo(snapshotId);
    }

    function test_PermissionsCheckForSigner(address signer, uint salt) public {
        UpgradeableModularAccount account = factory.createAccountWithAccessControl(admin1, salt);
        AccessControlPlugin _plugin = AccessControlPlugin(address(account));

        assertTrue(_plugin.hasRole(DEFAULT_ADMIN_ROLE, admin1));

        vm.startPrank(admin1);

        // grant signer to signer
        _plugin.grantRole(SIGNER_ROLE, signer);
        assertTrue(_plugin.hasRole(SIGNER_ROLE, signer));

        vm.startPrank(signer);

        uint snapshotId = vm.snapshot();

        vm.expectRevert();
        _plugin.grantRole(SIGNER_ROLE, address(1));

        vm.expectRevert();
        _plugin.setRolePermitAll(SIGNER_ROLE, true);

        vm.expectRevert();
        _plugin.setRoleAccess(SIGNER_ROLE, address(1), bytes4(0x12345678), true);

        vm.expectRevert();
        IAccessControlPlugin.Access[] memory accesses = new IAccessControlPlugin.Access[](1);
        accesses[0] = IAccessControlPlugin.Access(address(2), bytes4(0x12345678), true);
        _plugin.setRoleAccessBatch(SIGNER_ROLE, accesses);

        vm.expectRevert();
        _plugin.setRoleStopped(SIGNER_ROLE, true);

        vm.startPrank(admin1);

        vm.expectRevert();
        _plugin.checkAccess(signer, address(callee), bytes4(0x12345678));

        _plugin.setRolePermitAll(SIGNER_ROLE, true);
        _plugin.checkAccess(signer, address(callee), bytes4(0x12345678));

        vm.startPrank(signer);
        account.execute(Execution({
            target: address(callee),
            value: 0,
            data: abi.encode(bytes4(0x12345678))
        }));

        assertEq(callee.lastSender(), address(account));
        assertEq(callee.lastCalldata(), abi.encode(bytes4(0x12345678)));

        vm.revertTo(snapshotId);
    }

    function test_PermissionsCheckForAnyone() public {}

}