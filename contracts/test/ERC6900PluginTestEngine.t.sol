// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";
import "forge-std/console2.sol";

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import "@erc6900/reference-implementation/interfaces/IPlugin.sol";
import {UserOperation} from "@eth-infinitism/account-abstraction/interfaces/UserOperation.sol";
import "@eth-infinitism/account-abstraction/interfaces/IAccount.sol";


// import "contracts/src/interfaces/IModularAccount.sol";


library AddressArrayLib {
    function contains(address[] memory arr, address value) internal pure returns(bool) {
        for (uint i; i < arr.length; i++) {
            if (arr[i] == value) {
                return true;
            }
        }

        return false;
    }
}

contract ERC6900PluginTestEngine is Test {
    using ECDSA for bytes32;
    using AddressArrayLib for address[];

    struct Context {
        EntryPoint entryPoint;

        address account;
        IPlugin plugin;

        mapping(address => uint256) registeredAddress;
        TestCase[] cases;
    }

    struct TestCase {
        bytes4 selector;
        address[] senders;
        uint8 preUserOpValidation;
        uint8 preRuntimeValidation;
        uint8 userOpValidation;
        uint8 runtimeValidation;
    }

    uint8 constant VALIDATION_NOT_DEFINED = 252;
    uint8 constant VALIDATION_ALWAYS_DENY = 253;
    uint8 constant RUNTIME_VALIDATION_ALWAYS_ALLOW = 254;
    uint8 constant SKIP_VALIDATION = 255;

    Context internal ctx;

    function setUp() public virtual {
        ctx.entryPoint = new EntryPoint();
    }

    function setAccount(address account) internal {
        ctx.account = account;
    }

    function addPlugin(IPlugin _plugin) internal {
        ctx.plugin = _plugin;
    }

    function addTestCase(
        TestCase memory _case
    ) internal {
        ctx.cases.push(_case);
    }

    // TODO: Find out all of functions the plugin implemented to make sure well-tested.
    function assertAllFuncsBeingTested() external {
        assertTrue(true);
    }

    // function _test_PreRuntimeValidationHook(Context storage tcase, uint functionId, address sender, uint256 value, bytes calldata data) {
    //     functionId = vm.bound(functionId, 0, tcase.preRuntimeValidationHookFunctionIds.length-1);

    // }

    function test_PreUserOpValidation(uint salt, UserOperation memory userOp) external {
        uint length = ctx.cases.length;
        bytes memory rawData = userOp.callData;
        for (uint i; i < length;i++) {
            TestCase storage tcase = ctx.cases[i];
            if (tcase.preUserOpValidation == SKIP_VALIDATION || tcase.preUserOpValidation == VALIDATION_NOT_DEFINED) {
                continue;
            }

            userOp.callData = abi.encodePacked(tcase.selector, rawData);

            for (uint j; j < tcase.senders.length;j++) {
                address sender = tcase.senders[j];
                // in the case, sender cannot sign userOp.
                if (sender == ctx.account) {
                    continue;
                }
                console2.log(uint(5555));

                uint256 failed = executePreUserOpValidation(tcase.userOpValidation, sender, userOp);
                assertEq(failed, 0, "expect valid pre user operation");
            }
        }
    }

    function test_ValidateUserOpSig(uint salt, UserOperation memory userOp) external {
        console2.log(uint(1111));
        uint length = ctx.cases.length;
        bytes memory rawData = userOp.callData;
        for (uint i; i < length;i++) {
            console2.log(uint(2222));

            TestCase storage tcase = ctx.cases[i];
            if (tcase.userOpValidation == SKIP_VALIDATION) {
                continue;
            }

            console2.log(uint(3333));
            
            if (tcase.userOpValidation == VALIDATION_NOT_DEFINED) {
                // calling by entrypoint.
                userOp.callData = abi.encodePacked(tcase.selector, rawData);

                uint randIndex = bound(salt, 0, tcase.senders.length-1);
                (bytes memory signature, bytes32 userOpHash) = signUserOp(tcase.senders[randIndex], userOp);
                userOp.signature = signature;
                vm.startPrank(address(ctx.entryPoint));
                vm.expectRevert();
                IAccount(address(ctx.account)).validateUserOp(userOp,userOpHash, 0);
                vm.stopPrank();
                continue;
            }

            console2.log(uint(4444));

            userOp.callData = abi.encodePacked(tcase.selector, rawData);
            for (uint j; j < tcase.senders.length;j++) {
                address sender = tcase.senders[j];
                // in the case, sender cannot sign userOp.
                if (sender == ctx.account) {
                    continue;
                }
                console2.log(uint(5555));

                uint256 failed = executeUserOpValidation(tcase.userOpValidation, sender, userOp);
                assertEq(failed, 0, "expect valid user operation sig");
            }
        }
    }

    function test_ValidateUserOpSig_CounterCase(UserOperation memory userOp) external {
        (address anyone, ) = anyoneRole();
        uint length = ctx.cases.length;
        for (uint i; i < length;i++) {
            TestCase storage tcase = ctx.cases[i];
            
            if (tcase.senders.contains(anyone)) {
                continue;
            }
            (address sender, uint privateKey) = makeAddrAndKeyExclude(tcase.senders);

            uint256 failed = executeUserOpValidation(tcase.userOpValidation, sender, userOp);
            assertEq(failed, 1, "expect invalid user operation sig");
        }
    }

    function test_PreRuntimeValidation(uint salt, uint256 value, bytes calldata data) external {
        uint length = ctx.cases.length;
        for (uint i; i < length;i++) {
            TestCase storage tcase = ctx.cases[i];
            if (tcase.preRuntimeValidation == SKIP_VALIDATION || tcase.preRuntimeValidation == VALIDATION_NOT_DEFINED) {
                continue;
            }

            for (uint j; j < tcase.senders.length;j++) {
                address sender = tcase.senders[j];
                executePreRuntimeValidation(tcase.runtimeValidation, sender, value, abi.encodePacked(tcase.selector, data), false);
            }
        }
    }
    function test_ValidateRuntime(uint salt, uint256 value, bytes calldata data) external {
        uint length = ctx.cases.length;
        for (uint i; i < length;i++) {
            TestCase storage tcase = ctx.cases[i];
            // TODO: just skip when RUNTIME_VALIDATION_ALWAYS_ALLOW. But test this case in the future.
            if (tcase.runtimeValidation == SKIP_VALIDATION || tcase.runtimeValidation == RUNTIME_VALIDATION_ALWAYS_ALLOW) {
                continue;
            }

            if (tcase.runtimeValidation == VALIDATION_NOT_DEFINED) {
                uint randIndex = bound(salt, 0, tcase.senders.length-1);
                vm.startPrank(tcase.senders[randIndex]);
                vm.expectRevert();
                ctx.account.call{value: value}(abi.encodePacked(tcase.selector, data));
                vm.stopPrank();
                continue;
            }

            for (uint j; j < tcase.senders.length;j++) {
                address sender = tcase.senders[j];
                executeRuntimeValidation(tcase.runtimeValidation, sender, value, abi.encodePacked(tcase.selector, data), false);
            }
        }
    }

    function test_ValidateRuntime_CounterCase(uint256 value, bytes calldata data) external {
        (address anyone, ) = anyoneRole();

        uint length = ctx.cases.length;
        for (uint i; i < length;i++) {
            TestCase storage tcase = ctx.cases[i];
            // TODO: just skip when RUNTIME_VALIDATION_ALWAYS_ALLOW. But test this case in the future.
            if (tcase.runtimeValidation == SKIP_VALIDATION || tcase.runtimeValidation == RUNTIME_VALIDATION_ALWAYS_ALLOW) {
                continue;
            }
            if (tcase.senders.contains(anyone)) {
                continue;
            }
            (address sender, ) = makeAddrAndKeyExclude(tcase.senders);

            vm.expectRevert();
            executeRuntimeValidation(tcase.runtimeValidation, sender, value, abi.encodePacked(tcase.selector, data), false);
        }
    }

    function executePreRuntimeValidation(uint8 functionId, address sender, uint256 value, bytes memory data, bool expectRevert) internal {
        if (expectRevert) {
            vm.expectRevert();
        }

        vm.startPrank(ctx.account);
        ctx.plugin.preRuntimeValidationHook(functionId, sender, value, data);
        vm.stopPrank();
    }

    function executeRuntimeValidation(uint8 functionId, address sender, uint256 value, bytes memory data, bool expectRevert) internal {
        if (expectRevert) {
            vm.expectRevert();
        }

        vm.startPrank(ctx.account);
        ctx.plugin.runtimeValidationFunction(functionId, sender, value, data);
        vm.stopPrank();
    }

    function executePreUserOpValidation(uint8 functionId, address sender, UserOperation memory userOp) internal returns(uint failed) {
        (bytes memory signature, bytes32 userOpHash) = signUserOp(sender, userOp);

        // sig cannot cover the whole userop struct since userop struct has sig field
        userOp.signature = signature;

        vm.startPrank(ctx.account);
        failed = ctx.plugin.preUserOpValidationHook(
            functionId, userOp, userOpHash
        );
        vm.stopPrank();
    }

    function executeUserOpValidation(uint8 functionId, address sender, UserOperation memory userOp) internal returns(uint failed) {
        (bytes memory signature, bytes32 userOpHash) = signUserOp(sender, userOp);

        // sig cannot cover the whole userop struct since userop struct has sig field
        userOp.signature = signature;

        vm.startPrank(ctx.account);
        failed = ctx.plugin.userOpValidationFunction(
            functionId, userOp, userOpHash
        );
        vm.stopPrank();
    }

    function signUserOp(address sender, UserOperation memory userOp) internal returns(bytes memory signature, bytes32 userOpHash) {
        require(ctx.registeredAddress[sender] != 0, "Not registered sender");
        uint256 privateKey = ctx.registeredAddress[sender];
        
        userOpHash = ctx.entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, userOpHash.toEthSignedMessageHash());

        // sig cannot cover the whole userop struct since userop struct has sig field
        signature = abi.encodePacked(r, s, v);
    }

    function registerRole(string memory role) internal returns(address addr, uint256 privateKey) {
        (addr, privateKey) = makeAddrAndKey(role);
        ctx.registeredAddress[addr] = privateKey;
    }

    function anyoneRole() internal returns(address addr, uint256 privateKey) {
        (addr, privateKey) = registerRole("Anyone");
    }

    function isRoleRegistered(string memory role) internal returns(bool) {
        (address addr, ) = makeAddrAndKey(role);
        return ctx.registeredAddress[addr] != 0;
    }

    function makeAddrAndKeyExclude(address[] memory excludes) internal returns(address addr, uint256 privateKey) {
        for (uint i; ; i++) {
            string memory salt = vm.toString(i);
            (addr, privateKey) = makeAddrAndKey(salt);
            if (!excludes.contains(addr) && privateKey != 0) {
                break;
            }
        }
        ctx.registeredAddress[addr] = privateKey;
    }

    function test_SameAddrOnSameSalt(string memory salt) external {
        (address addr1, ) = makeAddrAndKey(salt);

        (address addr2,) = makeAddrAndKey(salt);

        assertEq(addr1, addr2);
    }
}