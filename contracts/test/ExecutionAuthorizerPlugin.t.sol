// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";
import "forge-std/console2.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import {UpgradeableModularAccount} from "@erc6900/reference-implementation/account/UpgradeableModularAccount.sol";
import "@erc6900/reference-implementation/interfaces/IPlugin.sol";
import {IPluginManager} from "@erc6900/reference-implementation/interfaces/IPluginManager.sol";
import {FunctionReference, FunctionReferenceLib} from "@erc6900/reference-implementation/libraries/FunctionReferenceLib.sol";
import {Execution} from "@erc6900/reference-implementation/libraries/ERC6900TypeUtils.sol";

import {UserOperation} from "@eth-infinitism/account-abstraction/interfaces/UserOperation.sol";
import {IStandardExecutor} from "@erc6900/reference-implementation/interfaces/IStandardExecutor.sol";

import {MultiSignerPlugin} from "contracts/src/MultiSignerPlugin.sol";
import "contracts/src/interfaces/IExecutionAuthorizerPlugin.sol";
import "contracts/src/interfaces/IMultiSignerPlugin.sol";
import "contracts/src/ExecutionAuthorizerPlugin.sol";
import "contracts/test/ERC6900PluginTestEngine.t.sol";
import "./mocks/MSCAFactoryFixture.sol";
import "./mocks/Callee.sol";

contract ExecutionAuthorizerPluginEngineTest is ERC6900PluginTestEngine {
    using ECDSA for bytes32;
    
    Callee public callee;
    MSCAFactoryFixture public factory;

    address owner;
    address signer;

    function setUp() public override {
        super.setUp();
        callee = new Callee();
        factory = new MSCAFactoryFixture(ctx.entryPoint);

        addPlugin(new ExecutionAuthorizerPlugin());

        setAccount(address(factory.createAccountWithMultiSigner(address(this), uint(123456))));

        (owner, ) = registerRole("Owner");
        address[] memory onlyOwner = new address[](1);
        onlyOwner[0] = owner;

        address[] memory onlyOwnerOrSelf = new address[](2);
        onlyOwnerOrSelf[0] = owner;
        onlyOwnerOrSelf[1] = ctx.account;
        
        (signer, ) = registerRole("Signer");
        address[] memory onlyOwnerOrSigner = new address[](2);
        onlyOwnerOrSigner[0] = owner;
        onlyOwnerOrSigner[1] = signer;

        // grant roles
        MultiSignerPlugin(address(ctx.account)).transferOwnership(owner);

        // TODO:
        // addTestCase(
        //     TestCase({
        //         selector: IExecutionAuthorizerPlugin.setPermitCall.selector,
        //         senders: onlyOwnerOrSelf,
        //         preUserOpValidation: VALIDATION_NOT_DEFINED, //uint8(IExecutionAuthorizerPlugin.FunctionId.PRE_USER_OP_VALIDATION_AUTH)
        //         preRuntimeValidation: VALIDATION_NOT_DEFINED,
        //         userOpValidation: uint8(IMultiSignerPlugin.FunctionId.USER_OP_VALIDATION_OWNER),
        //         runtimeValidation: uint8(IMultiSignerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
        //     })
        // );
    }


    function test_InstallExecutionAuthorizerPlugin() public {
        _installExecutionAuthorizerPlugin();
    }

    function _installExecutionAuthorizerPlugin() internal {
        assertEq(IMultiSignerPlugin(address(ctx.account)).owner(), owner);
        bytes32 manifestHash = keccak256(abi.encode(ctx.plugin.pluginManifest()));
        FunctionReference[] memory dependencies = new FunctionReference[](2);
        dependencies[0] = FunctionReferenceLib.pack(address(factory.multiSignerPlugin()), uint8(IMultiSignerPlugin.FunctionId.USER_OP_VALIDATION_OWNER));
        dependencies[1] = FunctionReferenceLib.pack(address(factory.multiSignerPlugin()), uint8(IMultiSignerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF));

        vm.startPrank(owner);
        IPluginManager(ctx.account).installPlugin({
            plugin: address(ctx.plugin),
            manifestHash: manifestHash,
            pluginInitData: "",
            dependencies: dependencies,
            injectedHooks: new IPluginManager.InjectedHook[](0)
        });
        vm.stopPrank();
    }
}

contract ExecutionAuthorizerPluginTest is Test {
    using ECDSA for bytes32;

    Callee public callee;
    EntryPoint public entryPoint;
    MSCAFactoryFixture public factory;

    IPlugin public plugin;
    UpgradeableModularAccount public account;
    
    function setUp() public {
        callee = new Callee();
        entryPoint = new EntryPoint();
        factory = new MSCAFactoryFixture(entryPoint);
        plugin = new ExecutionAuthorizerPlugin();
        account = factory.createAccountWithMultiSigner(address(this), uint(123456));
    }

    function test_InstallExecutionAuthorizerPlugin() public {
        _installExecutionAuthorizerPlugin();
    }

    function test_CallShouldNotBeAllowedIfWithoutAuth(address signer, bytes4 selector, bytes memory params) public {
        _installExecutionAuthorizerPlugin();
        IMultiSignerPlugin(address(account)).setSigner(signer, true);

        vm.startPrank(signer);


        bytes memory cdata = abi.encode(selector, params);
        Execution memory exec = Execution({
            target: address(callee),
            value: 0,
            data: cdata
        });

        vm.expectRevert();
        account.execute(exec);

        vm.expectRevert();
        Execution[] memory execs = new Execution[](1);
        execs[0] = exec;
        account.executeBatch(execs);
    }

    function test_CallShouldNotBeAllowedIfWithoutAuthForUserOp(string memory salt, UserOperation memory userOp, bytes4 selector, bytes memory params) public {
        _installExecutionAuthorizerPlugin();
        // range bound the possible set of priv keys
        (address signer, uint256 privateKey) = makeAddrAndKey(salt);

        IMultiSignerPlugin(address(account)).setSigner(signer, true);

        bytes memory cdata = abi.encode(selector, params);
        Execution memory exec = Execution({
            target: address(callee),
            value: 0,
            data: cdata
        });

        userOp.callData = abi.encodeWithSelector(IStandardExecutor.execute.selector, (exec));

        // Avoid to stack too deep.
        {
            bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, userOpHash.toEthSignedMessageHash());

            // sig cannot cover the whole userop struct since userop struct has sig field
            bytes memory signature = abi.encodePacked(r, s, v);
            userOp.signature = signature;

            uint failed = plugin.preUserOpValidationHook(uint8(IExecutionAuthorizerPlugin.FunctionId.PRE_USER_OP_VALIDATION_AUTH), userOp, userOpHash);
            assertEq(failed, 1);
        }

        // Avoid to stack too deep.
        {
            Execution[] memory execs = new Execution[](1);
            execs[0] = exec;
            userOp.callData = abi.encodeWithSelector(IStandardExecutor.executeBatch.selector, (execs));

            bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, userOpHash.toEthSignedMessageHash());

            // sig cannot cover the whole userop struct since userop struct has sig field
            userOp.signature = abi.encodePacked(r, s, v);
            uint failed = plugin.preUserOpValidationHook(uint8(IExecutionAuthorizerPlugin.FunctionId.PRE_USER_OP_VALIDATION_AUTH), userOp, userOpHash);
            assertEq(failed, 1);
        }
    }

    function test_CallShouldBeAllowed(address signer, bytes4 selector, bytes memory params) public {
        _installExecutionAuthorizerPlugin();
        IMultiSignerPlugin(address(account)).setSigner(signer, true);
        IExecutionAuthorizerPlugin(address(account)).setPermitCall(address(callee), selector, true);

        vm.startPrank(signer);

        uint snapshotId = vm.snapshot();

        bytes memory cdata = abi.encode(selector, params);
        Execution memory exec = Execution({
            target: address(callee),
            value: 0,
            data: cdata
        });

        account.execute(exec);
        assertEq(callee.lastSender(), address(account));
        assertEq(callee.lastCalldata(), cdata);

        vm.revertTo(snapshotId);

        Execution[] memory execs = new Execution[](1);
        execs[0] = exec;
        account.executeBatch(execs);
        assertEq(callee.lastSender(), address(account));
        assertEq(callee.lastCalldata(), cdata);
    }

    function test_CallShouldBeAllowedForUserOp(string memory salt, UserOperation memory userOp, bytes4 selector, bytes memory params) public {
        _installExecutionAuthorizerPlugin();
        // range bound the possible set of priv keys
        (address signer, uint256 privateKey) = makeAddrAndKey(salt);

        IMultiSignerPlugin(address(account)).setSigner(signer, true);

        IExecutionAuthorizerPlugin(address(account)).setPermitCall(address(callee), selector, true);

        bytes memory cdata = abi.encode(selector, params);
        Execution memory exec = Execution({
            target: address(callee),
            value: 0,
            data: cdata
        });

        userOp.callData = abi.encodeWithSelector(IStandardExecutor.execute.selector, (exec));

        // Avoid to stack too deep.
        {
            bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, userOpHash.toEthSignedMessageHash());

            // sig cannot cover the whole userop struct since userop struct has sig field
            bytes memory signature = abi.encodePacked(r, s, v);
            userOp.signature = signature;
            vm.startPrank(address(account));
            uint failed = plugin.preUserOpValidationHook(uint8(IExecutionAuthorizerPlugin.FunctionId.PRE_USER_OP_VALIDATION_AUTH), userOp, userOpHash);
            vm.stopPrank();
            assertEq(failed, 0);
        }

        // Avoid to stack too deep.
        {
            Execution[] memory execs = new Execution[](1);
            execs[0] = exec;

            userOp.callData = abi.encodeWithSelector(IStandardExecutor.executeBatch.selector, (execs));
            bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, userOpHash.toEthSignedMessageHash());

            // sig cannot cover the whole userop struct since userop struct has sig field
            userOp.signature = abi.encodePacked(r, s, v);

            vm.startPrank(address(account));
            uint failed = plugin.preUserOpValidationHook(uint8(IExecutionAuthorizerPlugin.FunctionId.PRE_USER_OP_VALIDATION_AUTH), userOp, userOpHash);
            vm.stopPrank();
            
            assertEq(failed, 0);
        }
    }

    function _installExecutionAuthorizerPlugin() internal {
        assertEq(IMultiSignerPlugin(address(account)).owner(), address(this));
        bytes32 manifestHash = keccak256(abi.encode(plugin.pluginManifest()));
        FunctionReference[] memory dependencies = new FunctionReference[](2);
        dependencies[0] = FunctionReferenceLib.pack(address(factory.multiSignerPlugin()), uint8(IMultiSignerPlugin.FunctionId.USER_OP_VALIDATION_OWNER));
        dependencies[1] = FunctionReferenceLib.pack(address(factory.multiSignerPlugin()), uint8(IMultiSignerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF));

        account.installPlugin({
            plugin: address(plugin),
            manifestHash: manifestHash,
            pluginInitData: "",
            dependencies: dependencies,
            injectedHooks: new IPluginManager.InjectedHook[](0)
        });
    }
}