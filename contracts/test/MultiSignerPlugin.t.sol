// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";
import "@erc6900/reference-implementation/interfaces/IStandardExecutor.sol";
import {IPluginManager} from "@erc6900/reference-implementation/interfaces/IPluginManager.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import {UserOperation} from "@eth-infinitism/account-abstraction/interfaces/UserOperation.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {UpgradeableModularAccount} from "@erc6900/reference-implementation/account/UpgradeableModularAccount.sol";
import "@erc6900/reference-implementation/interfaces/IPlugin.sol";

import {IMultiSignerPlugin} from "contracts/src/interfaces/IMultiSignerPlugin.sol";
import {MultiSignerPlugin} from "contracts/src/MultiSignerPlugin.sol";
import "contracts/test/ERC6900PluginTestEngine.t.sol";
import "./mocks/MSCAFactoryFixture.sol";
import {ContractOwner} from "./mocks/ContractOwner.sol";

contract MultiSignerPluginAccessTest is ERC6900PluginTestEngine {
    using ECDSA for bytes32;

    MultiSignerPlugin public plugin;
    MSCAFactoryFixture public factory;

    UpgradeableModularAccount public account;

    function setUp() public override {
        super.setUp();
        factory = new MSCAFactoryFixture(ctx.entryPoint);
        plugin = MultiSignerPlugin(address(factory.multiSignerPlugin()));

        account = factory.createAccountWithMultiSigner(address(this), uint(123456));

        addPlugin(plugin);
        setAccount(address(account));

        // register roles
        (address anyone, ) = anyoneRole();
        address[] memory nolimit = new address[](1);
        nolimit[0] = anyone;

        (address owner, ) = registerRole("Owner");
        address[] memory onlyOwner = new address[](1);
        onlyOwner[0] = owner;

        address[] memory onlyOwnerOrSelf = new address[](2);
        onlyOwnerOrSelf[0] = owner;
        onlyOwnerOrSelf[1] = address(account);
        
        (address signer, ) = registerRole("Signer");
        address[] memory onlyOwnerOrSigner = new address[](2);
        onlyOwnerOrSigner[0] = owner;
        onlyOwnerOrSigner[1] = signer;

        address[] memory onlyOwnerSignerOrSelf = new address[](3);
        onlyOwnerSignerOrSelf[0] = owner;
        onlyOwnerSignerOrSelf[1] = signer;
        onlyOwnerSignerOrSelf[2] = address(account);

        // grant roles
        MultiSignerPlugin(address(account)).transferOwnership(owner);

        vm.startPrank(owner);
        MultiSignerPlugin(address(account)).setSigner(signer, true);
        vm.stopPrank();

        addTestCase(
            TestCase({
                selector: plugin.transferOwnership.selector,
                senders: onlyOwnerOrSelf,
                preUserOpValidation: SKIP_VALIDATION,
                preRuntimeValidation: SKIP_VALIDATION,
                userOpValidation: uint8(IMultiSignerPlugin.FunctionId.USER_OP_VALIDATION_OWNER),
                runtimeValidation: uint8(IMultiSignerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
            })
        );

        addTestCase(
            TestCase({
                selector: plugin.isValidSignature.selector,
                senders: nolimit,
                preUserOpValidation: SKIP_VALIDATION,
                preRuntimeValidation: SKIP_VALIDATION,
                userOpValidation: VALIDATION_NOT_DEFINED,
                runtimeValidation: RUNTIME_VALIDATION_ALWAYS_ALLOW
            })
        );

        addTestCase(
            TestCase({
                selector: plugin.setSigner.selector,
                senders: onlyOwner,
                preUserOpValidation: SKIP_VALIDATION,
                preRuntimeValidation: SKIP_VALIDATION,
                userOpValidation: uint8(IMultiSignerPlugin.FunctionId.USER_OP_VALIDATION_OWNER),
                runtimeValidation: uint8(IMultiSignerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
            })
        );

        addTestCase(
            TestCase({
                selector: plugin.setRecoveryAddress.selector,
                senders: onlyOwner,
                preUserOpValidation: SKIP_VALIDATION,
                preRuntimeValidation: SKIP_VALIDATION,
                userOpValidation: uint8(IMultiSignerPlugin.FunctionId.USER_OP_VALIDATION_OWNER),
                runtimeValidation: uint8(IMultiSignerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
            })
        );

        addTestCase(
            TestCase({
                selector: plugin.recoverOwner.selector,
                senders: onlyOwner,
                preUserOpValidation: SKIP_VALIDATION,
                preRuntimeValidation: SKIP_VALIDATION,
                userOpValidation: uint8(IMultiSignerPlugin.FunctionId.USER_OP_VALIDATION_OWNER),
                runtimeValidation: uint8(IMultiSignerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
            })
        );

        addTestCase(
            TestCase({
                selector: plugin.owner.selector,
                senders: nolimit,
                preUserOpValidation: SKIP_VALIDATION,
                preRuntimeValidation: SKIP_VALIDATION,
                userOpValidation: VALIDATION_NOT_DEFINED,
                runtimeValidation: RUNTIME_VALIDATION_ALWAYS_ALLOW
            })
        );

        addTestCase(
            TestCase({
                selector: plugin.recoveryAddress.selector,
                senders: nolimit,
                preUserOpValidation: SKIP_VALIDATION,
                preRuntimeValidation: SKIP_VALIDATION,
                userOpValidation: VALIDATION_NOT_DEFINED,
                runtimeValidation: RUNTIME_VALIDATION_ALWAYS_ALLOW
            })
        );

        addTestCase(
            TestCase({
                selector: plugin.signersLength.selector,
                senders: nolimit,
                preUserOpValidation: SKIP_VALIDATION,
                preRuntimeValidation: SKIP_VALIDATION,
                userOpValidation: VALIDATION_NOT_DEFINED,
                runtimeValidation: RUNTIME_VALIDATION_ALWAYS_ALLOW
            })
        );

        addTestCase(
            TestCase({
                selector: plugin.signers.selector,
                senders: nolimit,
                preUserOpValidation: SKIP_VALIDATION,
                preRuntimeValidation: SKIP_VALIDATION,
                userOpValidation: VALIDATION_NOT_DEFINED,
                runtimeValidation: RUNTIME_VALIDATION_ALWAYS_ALLOW
            })
        );

        addTestCase(
            TestCase({
                selector: plugin.ownerOf.selector,
                senders: nolimit,
                preUserOpValidation: SKIP_VALIDATION,
                preRuntimeValidation: SKIP_VALIDATION,
                userOpValidation: VALIDATION_NOT_DEFINED,
                runtimeValidation: VALIDATION_NOT_DEFINED
            })
        );

        addTestCase(
            TestCase({
                selector: plugin.recoveryAddress.selector,
                senders: nolimit,
                preUserOpValidation: SKIP_VALIDATION,
                preRuntimeValidation: SKIP_VALIDATION,
                userOpValidation: VALIDATION_NOT_DEFINED,
                runtimeValidation: VALIDATION_NOT_DEFINED
            })
        );

        addTestCase(
            TestCase({
                selector: plugin.signersLength.selector,
                senders: nolimit,
                preUserOpValidation: SKIP_VALIDATION,
                preRuntimeValidation: SKIP_VALIDATION,
                userOpValidation: VALIDATION_NOT_DEFINED,
                runtimeValidation: VALIDATION_NOT_DEFINED
            })
        );

        addTestCase(
            TestCase({
                selector: plugin.signers.selector,
                senders: nolimit,
                preUserOpValidation: SKIP_VALIDATION,
                preRuntimeValidation: SKIP_VALIDATION,
                userOpValidation: VALIDATION_NOT_DEFINED,
                runtimeValidation: VALIDATION_NOT_DEFINED
            })
        );

        addTestCase(
            TestCase({
                selector: plugin.onInstall.selector,
                senders: nolimit,
                preUserOpValidation: SKIP_VALIDATION,
                preRuntimeValidation: SKIP_VALIDATION,
                userOpValidation: VALIDATION_NOT_DEFINED,
                runtimeValidation: VALIDATION_NOT_DEFINED
            })
        );

        addTestCase(
            TestCase({
                selector: plugin.onUninstall.selector,
                senders: nolimit,
                preUserOpValidation: SKIP_VALIDATION,
                preRuntimeValidation: SKIP_VALIDATION,
                userOpValidation: VALIDATION_NOT_DEFINED,
                runtimeValidation: VALIDATION_NOT_DEFINED
            })
        );

        addTestCase(
            TestCase({
                selector: plugin.supportsInterface.selector,
                senders: nolimit,
                preUserOpValidation: SKIP_VALIDATION,
                preRuntimeValidation: SKIP_VALIDATION,
                userOpValidation: VALIDATION_NOT_DEFINED,
                runtimeValidation: VALIDATION_NOT_DEFINED
            })
        );

        addTestCase(
            TestCase({
                selector: IStandardExecutor.execute.selector,
                senders: onlyOwnerSignerOrSelf,
                preUserOpValidation: SKIP_VALIDATION,
                preRuntimeValidation: SKIP_VALIDATION,
                userOpValidation: uint8(IMultiSignerPlugin.FunctionId.USER_OP_VALIDATION_OWNER_OR_SIGNER),
                runtimeValidation: uint8(IMultiSignerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_SIGNER_OR_SELF)
            })
        );

        addTestCase(
            TestCase({
                selector: IStandardExecutor.executeBatch.selector,
                senders: onlyOwnerSignerOrSelf,
                preUserOpValidation: SKIP_VALIDATION,
                preRuntimeValidation: SKIP_VALIDATION,
                userOpValidation: uint8(IMultiSignerPlugin.FunctionId.USER_OP_VALIDATION_OWNER_OR_SIGNER),
                runtimeValidation: uint8(IMultiSignerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_SIGNER_OR_SELF)
            })
        );

        addTestCase(
            TestCase({
                selector: IPluginManager.installPlugin.selector,
                senders: onlyOwnerOrSigner,
                preUserOpValidation: SKIP_VALIDATION,
                preRuntimeValidation: SKIP_VALIDATION,
                userOpValidation: uint8(IMultiSignerPlugin.FunctionId.USER_OP_VALIDATION_OWNER_OR_SIGNER),
                runtimeValidation: uint8(IMultiSignerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_SIGNER_OR_SELF)
            })
        );

        addTestCase(
            TestCase({
                selector: IPluginManager.uninstallPlugin.selector,
                senders: onlyOwnerOrSigner,
                preUserOpValidation: SKIP_VALIDATION,
                preRuntimeValidation: SKIP_VALIDATION,
                userOpValidation: uint8(IMultiSignerPlugin.FunctionId.USER_OP_VALIDATION_OWNER_OR_SIGNER),
                runtimeValidation: uint8(IMultiSignerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_SIGNER_OR_SELF)
            })
        );

        addTestCase(
            TestCase({
                selector: UUPSUpgradeable.upgradeTo.selector,
                senders: onlyOwnerOrSigner,
                preUserOpValidation: SKIP_VALIDATION,
                preRuntimeValidation: SKIP_VALIDATION,
                userOpValidation: uint8(IMultiSignerPlugin.FunctionId.USER_OP_VALIDATION_OWNER_OR_SIGNER),
                runtimeValidation: uint8(IMultiSignerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_SIGNER_OR_SELF)
            })
        );

        addTestCase(
            TestCase({
                selector: UUPSUpgradeable.upgradeToAndCall.selector,
                senders: onlyOwnerOrSigner,
                preUserOpValidation: SKIP_VALIDATION,
                preRuntimeValidation: SKIP_VALIDATION,
                userOpValidation: uint8(IMultiSignerPlugin.FunctionId.USER_OP_VALIDATION_OWNER_OR_SIGNER),
                runtimeValidation: uint8(IMultiSignerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_SIGNER_OR_SELF)
            })
        );
    }
}

contract MultiSignerPluginTest is Test {
    using ECDSA for bytes32;

    EntryPoint public entryPoint;
    MultiSignerPlugin public plugin;
    MSCAFactoryFixture public factory;

    UpgradeableModularAccount public account;

    bytes4 internal constant _1271_MAGIC_VALUE = 0x1626ba7e;
    address public a;
    address public b;

    address public owner1;
    address public owner2;
    ContractOwner public contractOwner;

    // Event declarations (needed for vm.expectEmit)
    event OwnershipTransferred(address indexed account, address indexed previousOwner, address indexed newOwner);

    function setUp() public {
        entryPoint = new EntryPoint();
        factory = new MSCAFactoryFixture(entryPoint);
        plugin = MultiSignerPlugin(address(factory.multiSignerPlugin()));

        account = factory.createAccountWithMultiSigner(address(this), uint(123456));

        a = makeAddr("a");
        b = makeAddr("b");
        owner1 = makeAddr("owner1");
        owner2 = makeAddr("owner2");
        contractOwner = new ContractOwner();
    }

    // Tests:
    // - uninitialized owner is zero address
    // - transferOwnership result is returned via owner afterwards
    // - transferOwnership emits OwnershipTransferred event
    // - owner() returns correct value after transferOwnership
    // - owner() does not return a different account's owner
    // - requireFromOwner succeeds when called by owner
    // - requireFromOwner reverts when called by non-owner

    function test_UninitializedOwner() public {
        vm.startPrank(a);
        assertEq(address(0), plugin.owner());
    }

    function test_OwnerInitialization() public {
        vm.startPrank(a);
        assertEq(address(0), plugin.owner());
        plugin.transferOwnership(owner1);
        assertEq(owner1, plugin.owner());
    }

    function test_OwnerInitializationEvent() public {
        vm.startPrank(a);
        assertEq(address(0), plugin.owner());

        vm.expectEmit(true, true, true, true);
        emit OwnershipTransferred(a, address(0), owner1);

        plugin.transferOwnership(owner1);
        assertEq(owner1, plugin.owner());
    }

    function test_OwnerMigration() public {
        vm.startPrank(a);
        assertEq(address(0), plugin.owner());
        plugin.transferOwnership(owner1);
        assertEq(owner1, plugin.owner());
        plugin.transferOwnership(owner2);
        assertEq(owner2, plugin.owner());
    }

    function test_OwnerMigrationEvents() public {
        vm.startPrank(a);
        assertEq(address(0), plugin.owner());

        vm.expectEmit(true, true, true, true);
        emit OwnershipTransferred(a, address(0), owner1);

        plugin.transferOwnership(owner1);
        assertEq(owner1, plugin.owner());

        vm.expectEmit(true, true, true, true);
        emit OwnershipTransferred(a, owner1, owner2);

        plugin.transferOwnership(owner2);
        assertEq(owner2, plugin.owner());
    }

    function test_OwnerForSender() public {
        vm.startPrank(a);
        assertEq(address(0), plugin.owner());
        plugin.transferOwnership(owner1);
        assertEq(owner1, plugin.owner());
        vm.startPrank(b);
        assertEq(address(0), plugin.owner());
        plugin.transferOwnership(owner2);
        assertEq(owner2, plugin.owner());
    }

    function test_RequireOwner() public {
        vm.startPrank(a);
        assertEq(address(0), plugin.owner());
        plugin.transferOwnership(owner1);
        assertEq(owner1, plugin.owner());
        plugin.runtimeValidationFunction(
            uint8(IMultiSignerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_SIGNER_OR_SELF), owner1, 0, ""
        );

        vm.startPrank(b);
        vm.expectRevert(IMultiSignerPlugin.NotAuthorized.selector);
        plugin.runtimeValidationFunction(
            uint8(IMultiSignerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_SIGNER_OR_SELF), owner1, 0, ""
        );
    }

    function testFuzz_ValidateUserOpSigForOwner(string memory salt, UserOperation memory userOp) public {
        // range bound the possible set of priv keys
        (address owner, uint256 privateKey) = makeAddrAndKey(salt);

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, userOpHash.toEthSignedMessageHash());

        // sig cannot cover the whole userop struct since userop struct has sig field
        userOp.signature = abi.encodePacked(r, s, v);

        vm.startPrank(a);

        // sig check should fail
        uint256 success = plugin.userOpValidationFunction(
            uint8(IMultiSignerPlugin.FunctionId.USER_OP_VALIDATION_OWNER_OR_SIGNER), userOp, userOpHash
        );
        assertEq(success, 1);

        // transfer ownership to signer
        plugin.transferOwnership(owner);
        assertEq(owner, plugin.owner());

        // sig check should pass
        success = plugin.userOpValidationFunction(
            uint8(IMultiSignerPlugin.FunctionId.USER_OP_VALIDATION_OWNER_OR_SIGNER), userOp, userOpHash
        );
        assertEq(success, 0);
    }

    function testFuzz_ValidateUserOpSigForSigner(string memory salt, UserOperation memory userOp) public {
        (address signer, uint256 privateKey) = makeAddrAndKey(salt);

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, userOpHash.toEthSignedMessageHash());

        // sig cannot cover the whole userop struct since userop struct has sig field
        userOp.signature = abi.encodePacked(r, s, v);

        // sig check should fail
        uint256 success = plugin.userOpValidationFunction(
            uint8(IMultiSignerPlugin.FunctionId.USER_OP_VALIDATION_OWNER_OR_SIGNER), userOp, userOpHash
        );
        assertEq(success, 1);

        plugin.setSigner(signer, true);

        // sig check should pass
        success = plugin.userOpValidationFunction(
            uint8(IMultiSignerPlugin.FunctionId.USER_OP_VALIDATION_OWNER_OR_SIGNER), userOp, userOpHash
        );
        assertEq(success, 0);
    }

    function testFuzz_IsValidSignatureForEOAOwner(string memory salt, bytes32 digest) public {
        // range bound the possible set of priv keys
        (address signer, uint256 privateKey) = makeAddrAndKey(salt);

        vm.startPrank(a);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);

        // sig check should fail
        assertEq(plugin.isValidSignature(digest, abi.encodePacked(r, s, v)), bytes4(0xFFFFFFFF));

        // transfer ownership to signer
        plugin.transferOwnership(signer);
        assertEq(signer, plugin.owner());

        // sig check should pass
        assertEq(plugin.isValidSignature(digest, abi.encodePacked(r, s, v)), _1271_MAGIC_VALUE);
    }

    function testFuzz_IsValidSignatureForContractOwner(bytes32 digest) public {
        vm.startPrank(a);
        plugin.transferOwnership(address(contractOwner));
        bytes memory signature = contractOwner.sign(digest);
        assertEq(plugin.isValidSignature(digest, signature), _1271_MAGIC_VALUE);
    }

    function test_RecoverOwner() public {
        address recovery = a;
        MultiSignerPlugin(address(account)).transferOwnership(owner1);
        assertEq(owner1, MultiSignerPlugin(address(account)).owner());

        // Checks `setRecoveryAddress` can only be called by owner
        vm.expectRevert();
        MultiSignerPlugin(address(account)).setRecoveryAddress(recovery);

        vm.startPrank(owner1);
        MultiSignerPlugin(address(account)).setRecoveryAddress(recovery);

        // We skip 1 second to avoid that block.timestamp is equal to 0.
        skip(1 seconds);

        // Checks `recoverOwner` can only be called by recovery
        vm.expectRevert();
        MultiSignerPlugin(address(account)).recoverOwner();

        vm.startPrank(recovery);
        MultiSignerPlugin(address(account)).recoverOwner();

        skip(1 days);
        MultiSignerPlugin(address(account)).recoverOwner();

        assertEq(recovery, MultiSignerPlugin(address(account)).owner());
    }
}
