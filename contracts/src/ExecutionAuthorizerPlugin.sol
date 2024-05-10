// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import {BasePlugin} from "@erc6900/reference-implementation/plugins/BasePlugin.sol";
import {Execution} from "@erc6900/reference-implementation/libraries/ERC6900TypeUtils.sol";
import {IStandardExecutor} from "@erc6900/reference-implementation/interfaces/IStandardExecutor.sol";
import {IPluginManager} from "@erc6900/reference-implementation/interfaces/IPluginManager.sol";
import {
    ManifestFunction,
    ManifestAssociatedFunctionType,
    ManifestAssociatedFunction,
    PluginManifest,
    ManifestExecutionFunction,
    IPlugin
} from "@erc6900/reference-implementation/interfaces/IPlugin.sol";
import "contracts/src/interfaces/IMultiSignerPlugin.sol";
import "contracts/src/interfaces/IExecutionAuthorizerPlugin.sol";

contract ExecutionAuthorizerPlugin is BasePlugin, IExecutionAuthorizerPlugin {
    using ECDSA for bytes32;

    string public constant NAME = "Execution Authorizer Plugin";
    string public constant VERSION = "1.0.0";
    string public constant AUTHOR = "Ivan Zhang";

    uint256 internal constant _SIG_VALIDATION_PASSED = 0;
    uint256 internal constant _SIG_VALIDATION_FAILED = 1;

    mapping(address => mapping(address => mapping(bytes4 => bool))) private _permitCalls;

    function setPermitCall(address target, bytes4 selector, bool enable) external override {
        _permitCalls[msg.sender][target][selector] = enable;
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc BasePlugin
    function onInstall(bytes calldata) external override {}

    /// @inheritdoc BasePlugin
    function onUninstall(bytes calldata) external override {}

    // @inheritdoc BasePlugin
    function preRuntimeValidationHook(uint8 functionId, address sender, uint256, bytes calldata data) external view override {
        // If the functionId is the preRuntimeValidationAuth function, then we need to check if the sender is the owner of the contract.
        if (functionId == uint8(FunctionId.PRE_RUNTIME_VALIDATION_AUTH)) {
            // Get the owner of the contract.
            // In case the `owner` function of the contract is not defined, we need to use try-catch.
            address owner;
            try IMultiSignerPlugin(msg.sender).owner() returns(address _owner) {
                owner = _owner;
            } catch {}

            // If the sender is the owner, then return.
            if (sender == owner) {
                return;
            }

            // Get the selector of the data.
            bytes4 selector = bytes4(data[:4]);
            // If the selector is the execute function, then decode the data and check if the target is authorized.
            if (selector == IStandardExecutor.execute.selector) {
                Execution memory exec = abi.decode(data[4:], (Execution));

                // Check if the target is authorized.
                if (!_permitCalls[msg.sender][exec.target][bytes4(exec.data)]) {
                    revert NotAuthorized();
                }

                return;
            // If the selector is the executeBatch function, then decode the data and check if the targets are authorized.
            } else if (selector == IStandardExecutor.executeBatch.selector) {
                Execution[] memory execs = abi.decode(data[4:], (Execution[]));
                uint length = execs.length;
                for (uint i; i < length;) {
                    Execution memory exec = execs[i];

                    // Check if the target is authorized.
                    if (!_permitCalls[msg.sender][exec.target][bytes4(exec.data)]) {
                        revert NotAuthorized();
                    }
                    unchecked {
                        ++i;
                    }
                }

                return;
            }
        }

        // If the functionId is not the preRuntimeValidationAuth function, then revert the NotImplemented error.
        revert NotImplemented();
    }

    // @inheritdoc BasePlugin
    // This function is used to validate a user operation before it is executed.
    function preUserOpValidationHook(uint8 functionId, UserOperation calldata userOp, bytes32 userOpHash) external view override returns (uint256) {
        // If the function ID is the PRE_USER_OP_VALIDATION_AUTH function, then validate the user op signature.
        if (functionId == uint8(FunctionId.PRE_USER_OP_VALIDATION_AUTH)) {
            // Get the owner of the multi-signer plugin.
            address owner;
            try IMultiSignerPlugin(msg.sender).owner() returns(address _owner) {
                owner = _owner;
            } catch {}


            // Validate the user op signature against the owner.
            (address signer,) = (userOpHash.toEthSignedMessageHash()).tryRecover(userOp.signature);
            if (signer == address(0)) {
                return _SIG_VALIDATION_FAILED;
            }

            // If the signer is the owner, then the signature is valid.
            if (signer == owner) {
                return _SIG_VALIDATION_PASSED;
            }

            // Get the selector of the user op.
            bytes4 selector = bytes4(userOp.callData);

            // If the selector is the execute function, then validate the execution.
            if (selector == IStandardExecutor.execute.selector) {
                // Decode the execution data.
                Execution memory exec = abi.decode(userOp.callData[4:], (Execution));

                // Check if the call is authorized.
                if (!_permitCalls[msg.sender][exec.target][bytes4(exec.data)]) {
                    return _SIG_VALIDATION_FAILED;
                }

                return _SIG_VALIDATION_PASSED;
            // If the selector is the executeBatch function, then validate the executions.
            } else if (selector == IStandardExecutor.executeBatch.selector) {
                // Decode the execution data.
                Execution[] memory execs = abi.decode(userOp.callData[4:], (Execution[]));
                uint length = execs.length;
                for (uint i; i < length;) {
                    Execution memory exec = execs[i];

                    // Check if the call is authorized.
                    if (!_permitCalls[msg.sender][exec.target][bytes4(exec.data)]) {
                        return _SIG_VALIDATION_FAILED;
                    }
                    unchecked {
                        ++i;
                    }
                }

                return _SIG_VALIDATION_PASSED;
            }

            // If the selector is not recognized, then the signature is invalid.
            return _SIG_VALIDATION_FAILED;
        }
        // If the function ID is not recognized, then revert.
        revert NotImplemented();
    }

    // @inheritdoc BasePlugin
    function pluginManifest() external pure override returns (PluginManifest memory) {
        // Create a PluginManifest memory object.
        PluginManifest memory manifest;

        // Set the name, version, and author of the PluginManifest.
        manifest.name = NAME;
        manifest.version = VERSION;
        manifest.author = AUTHOR;

        // Set the dependency interface IDs.
        manifest.dependencyInterfaceIds = new bytes4[](2);
        manifest.dependencyInterfaceIds[0] = type(IPlugin).interfaceId;
        manifest.dependencyInterfaceIds[1] = type(IPlugin).interfaceId;

        // Set the execution functions.
        manifest.executionFunctions = new ManifestExecutionFunction[](1);
        manifest.executionFunctions[0] = ManifestExecutionFunction(this.setPermitCall.selector, new string[](0));

        // Set the user op validation function.
        ManifestFunction memory ownerUserOpValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.DEPENDENCY,
            functionId: uint8(123),
            dependencyIndex: 0
        });

        manifest.userOpValidationFunctions = new ManifestAssociatedFunction[](1);
        manifest.userOpValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.setPermitCall.selector,
            associatedFunction: ownerUserOpValidationFunction
        });

        // Set the runtime validation functions.
        ManifestFunction memory ownerRuntimeValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.DEPENDENCY,
            functionId: uint8(124),
            dependencyIndex: 1
        });

        manifest.runtimeValidationFunctions = new ManifestAssociatedFunction[](1);
        manifest.runtimeValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.setPermitCall.selector,
            associatedFunction: ownerRuntimeValidationFunction
        });

        // Set the pre runtime validation hooks.
        ManifestFunction memory authPreRuntimeValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.SELF,
            functionId: uint8(FunctionId.PRE_RUNTIME_VALIDATION_AUTH),
            dependencyIndex: 0 // Unused.
        });
        manifest.preRuntimeValidationHooks = new ManifestAssociatedFunction[](2);
        manifest.preRuntimeValidationHooks[0] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.execute.selector,
            associatedFunction: authPreRuntimeValidationFunction
        });
        manifest.preRuntimeValidationHooks[1] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.executeBatch.selector,
            associatedFunction: authPreRuntimeValidationFunction
        });

        // Set the pre user op validation hooks.
        ManifestFunction memory authPreUserOpValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.SELF,
            functionId: uint8(FunctionId.PRE_USER_OP_VALIDATION_AUTH),
            dependencyIndex: 0 // Unused.
        });
        manifest.preUserOpValidationHooks = new ManifestAssociatedFunction[](2);
        manifest.preUserOpValidationHooks[0] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.execute.selector,
            associatedFunction: authPreUserOpValidationFunction
        });
        manifest.preUserOpValidationHooks[1] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.executeBatch.selector,
            associatedFunction: authPreUserOpValidationFunction
        });

        // Return the PluginManifest.
        return manifest;
    }

    // ┏━━━━━━━━━━━━━━━┓
    // ┃    EIP-165    ┃
    // ┗━━━━━━━━━━━━━━━┛

    /// @inheritdoc BasePlugin
    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
        return interfaceId == type(IExecutionAuthorizerPlugin).interfaceId || super.supportsInterface(interfaceId);
    }
}