// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;


import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

import {UserOperation} from "@eth-infinitism/account-abstraction/interfaces/UserOperation.sol";

import {BasePlugin} from "@erc6900/reference-implementation/plugins/BasePlugin.sol";
import {IStandardExecutor} from "@erc6900/reference-implementation/interfaces/IStandardExecutor.sol";
import {IPluginManager} from "@erc6900/reference-implementation/interfaces/IPluginManager.sol";
import {
    ManifestFunction,
    ManifestAssociatedFunctionType,
    ManifestAssociatedFunction,
    PluginManifest,
    ManifestExecutionFunction
} from "@erc6900/reference-implementation/interfaces/IPlugin.sol";

import "contracts/src/interfaces/IMultiSignerPlugin.sol";

contract MultiSignerPlugin is BasePlugin, IMultiSignerPlugin, IERC1271 {
    using ECDSA for bytes32;
    using EnumerableSet for EnumerableSet.AddressSet;

    string public constant NAME = "Multiple Signer Plugin";
    string public constant VERSION = "1.0.0";
    string public constant AUTHOR = "Ivan Zhang";

    uint256 internal constant _SIG_VALIDATION_PASSED = 0;
    uint256 internal constant _SIG_VALIDATION_FAILED = 1;

    uint256 internal constant _RECOVERY_DELAY = 1 days;

    // bytes4(keccak256("isValidSignature(bytes32,bytes)"))
    bytes4 internal constant _1271_MAGIC_VALUE = 0x1626ba7e;

    struct Info {
        address owner;
        address recoveryAddress;
        uint lastRecovery;
        EnumerableSet.AddressSet signers;
    }

    mapping(address => Info) internal _infos;

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Execution functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc IMultiSignerPlugin
    function transferOwnership(address newOwner) external {
        _transferOwnership(newOwner);
    }

    /// @inheritdoc IERC1271
    /// @dev The signature is valid if it is signed by the owner's private key
    /// (if the owner is an EOA) or if it is a valid ERC-1271 signature from the
    /// owner (if the owner is a contract). Note that unlike the signature
    /// validation used in `validateUserOp`, this does///*not** wrap the digest in
    /// an "Ethereum Signed Message" envelope before checking the signature in
    /// the EOA-owner case.
    function isValidSignature(bytes32 digest, bytes memory signature) public view override returns (bytes4) {
        if (SignatureChecker.isValidSignatureNow(_infos[msg.sender].owner, digest, signature)) {
            return _1271_MAGIC_VALUE;
        }
        return 0xffffffff;
    }

    //This function sets a signer to either enable or disable a signer
    function setSigner(address signer, bool enable) external {
        //If enable is true, add the signer to the signers list
        if (enable) {
            _infos[msg.sender].signers.add(signer);
        //Otherwise, remove the signer from the signers list
        } else {
            _infos[msg.sender].signers.remove(signer);
        }
    }

    function setRecoveryAddress(address addr) external {
        // Get the info of the account
        Info storage info = _infos[msg.sender];
        // Check if the account is already in a recovery period
        if (info.lastRecovery != 0) {
            // If so, throw an error
            revert NotAllowedDuringRecovery();
        }
    
        if (info.owner == addr) { revert InvalidRecoveryAddress(); }
        info.recoveryAddress = addr;
    }

    // Can be called only by recoveryAddress
    // This function allows the recovery address to recover their account.
    function recoverOwner() external {
        // Get the info for the current owner
        Info storage info = _infos[msg.sender];
        // Check that the recovery address is not the zero address
        if (info.recoveryAddress == address(0)) { revert NotAllowedForZeroAddress(); }
        // If the recovery address has not yet recovered the account, set the last recovery time to the current block timestamp
        if (info.lastRecovery == 0) {
            info.lastRecovery = block.timestamp;
            return;
        }
        
        // Check that the last recovery time plus the delay is less than the current block timestamp
        if (info.lastRecovery + _RECOVERY_DELAY > block.timestamp) { revert NotTimeYet(); }

        // Reset the last recovery time to 0
        info.lastRecovery = 0;
        // Transfer ownership to the recovery address
        _transferOwnership(info.recoveryAddress);
    }

    function owner() external view returns (address) {
        return _infos[msg.sender].owner;
    }

    function recoveryAddress() external view returns (address) {
        return _infos[msg.sender].recoveryAddress;
    }

    function signersLength() external view returns (uint) {
        return _infos[msg.sender].signers.length();
    }

    function signers(uint i) external view returns (address) {
        return _infos[msg.sender].signers.at(i);
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin view functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function ownerOf(address account) external view returns (address) {
        return _infos[account].owner;
    }

    function recoveryAddrOf(address account) external view returns (address) {
        return _infos[account].recoveryAddress;
    }

    function signersLengthOf(address account) external view returns (uint) {
        return _infos[account].signers.length();
    }

    function signersOf(address account, uint i) external view returns (address) {
        return _infos[account].signers.at(i);
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc BasePlugin
    function onInstall(bytes calldata data) external override {
        _transferOwnership(abi.decode(data, (address)));
    }

    /// @inheritdoc BasePlugin
    function onUninstall(bytes calldata) external override {
        _transferOwnership(address(0));
    }

    /// @inheritdoc BasePlugin
   function runtimeValidationFunction(uint8 functionId, address sender, uint256, bytes calldata data)
        external
        view
        override
    {
        Info storage info = _infos[msg.sender];
        // Only `recoverOwner` can be called during recovery.
        if (info.lastRecovery != 0 && bytes4(data) != this.recoverOwner.selector) {
            revert NotAllowedDuringRecovery();
        }

        if (functionId == uint8(FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)) {
            // Validate that the sender is self.
            if (sender == msg.sender) {
                return;
            }

            // Validate that the sender is the owner of the account.
            if (sender == info.owner) {
                return;
            }

            // The sender is not the owner of the account or self.
            revert NotAuthorized();
        } else if (functionId == uint8(FunctionId.RUNTIME_VALIDATION_OWNER_SIGNER_OR_SELF)) {
            // Validate that the sender is self.
            if (sender == msg.sender) {
                return;
            }

            // Validate that the sender is the owner of the account.
            if (sender == info.owner) {
                return;
            }

            // Validate that the sender is the owner of the account or self.
            if (info.signers.contains(sender)) {
                return;
            }

            // The sender is not the owner of the account or self.
            revert NotAuthorized();
        } else if (functionId == uint8(FunctionId.RUNTIME_VALIDATION_RECOVERY)) {
            // Validate that the sender is the recovery address.
            if (sender == info.recoveryAddress) {
                return;
            }

            // The sender is not the recovery address.
            revert NotAuthorized();
        }

        // The function is not implemented.
        revert NotImplemented();
    }

    /// @inheritdoc BasePlugin
    function userOpValidationFunction(uint8 functionId, UserOperation calldata userOp, bytes32 userOpHash)
        external
        view
        override
        returns (uint256)
    {
        Info storage info = _infos[msg.sender];
        if (info.lastRecovery != 0 && bytes4(userOp.callData) != this.recoverOwner.selector) {
            revert NotAllowedDuringRecovery();
        }
        // Validate the user op signature against the owner.
        (address signer,) = (userOpHash.toEthSignedMessageHash()).tryRecover(userOp.signature);
        if (signer == address(0)) {
            return _SIG_VALIDATION_FAILED;
        }

        if (functionId == uint8(FunctionId.USER_OP_VALIDATION_OWNER)) {
            if (signer != info.owner) {
                return _SIG_VALIDATION_FAILED;
            }
            return _SIG_VALIDATION_PASSED;
        } else if (functionId == uint8(FunctionId.USER_OP_VALIDATION_OWNER_OR_SIGNER)) {
            if (signer != info.owner && !info.signers.contains(signer)) {
                return _SIG_VALIDATION_FAILED;
            }
            return _SIG_VALIDATION_PASSED;
        } else if (functionId == uint8(FunctionId.USER_OP_VALIDATION_RECOVERY)) {
            if (signer != info.recoveryAddress) {
                return _SIG_VALIDATION_FAILED;
            }
        }
        revert NotImplemented();
    }

    /// @inheritdoc BasePlugin
    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        // Set the manifest's name, version, and author.
        manifest.name = NAME;
        manifest.version = VERSION;
        manifest.author = AUTHOR;

        // Create an array of strings to represent the owner permissions.
        string[] memory ownerPermissions = new string[](1);
        ownerPermissions[0] = "OnlyOwner";

        // Create an array of strings to represent the recovery permissions.
        string[] memory recoveryPermissions = new string[](1);
        recoveryPermissions[0] = "OnlyRecovery";

        // Create an array of ManifestExecutionFunction structs to represent the execution functions.
        manifest.executionFunctions = new ManifestExecutionFunction[](10);
        manifest.executionFunctions[0] =
            ManifestExecutionFunction(this.transferOwnership.selector, ownerPermissions);
        manifest.executionFunctions[1] =
            ManifestExecutionFunction(this.setSigner.selector, ownerPermissions);
        manifest.executionFunctions[3] =
            ManifestExecutionFunction(this.setRecoveryAddress.selector, ownerPermissions);
        manifest.executionFunctions[4] = ManifestExecutionFunction(this.isValidSignature.selector, new string[](0));
        manifest.executionFunctions[5] = ManifestExecutionFunction(this.owner.selector, new string[](0));
        manifest.executionFunctions[6] = ManifestExecutionFunction(this.recoveryAddress.selector, new string[](0));
        manifest.executionFunctions[7] = ManifestExecutionFunction(this.signersLength.selector, new string[](0));
        manifest.executionFunctions[8] = ManifestExecutionFunction(this.signers.selector, new string[](0));
        manifest.executionFunctions[9] = ManifestExecutionFunction(this.recoverOwner.selector, recoveryPermissions);
        

        ManifestFunction memory ownerUserOpValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.SELF,
            functionId: uint8(FunctionId.USER_OP_VALIDATION_OWNER),
            dependencyIndex: 0 // Unused.
        });

        ManifestFunction memory ownerSignerUserOpValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.SELF,
            functionId: uint8(FunctionId.USER_OP_VALIDATION_OWNER_OR_SIGNER),
            dependencyIndex: 0 // Unused.
        });

        manifest.userOpValidationFunctions = new ManifestAssociatedFunction[](9);
        manifest.userOpValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.transferOwnership.selector,
            associatedFunction: ownerUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[1] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.execute.selector,
            associatedFunction: ownerSignerUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[2] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.executeBatch.selector,
            associatedFunction: ownerSignerUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[3] = ManifestAssociatedFunction({
            executionSelector: IPluginManager.installPlugin.selector,
            associatedFunction: ownerUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[4] = ManifestAssociatedFunction({
            executionSelector: IPluginManager.uninstallPlugin.selector,
            associatedFunction: ownerUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[5] = ManifestAssociatedFunction({
            executionSelector: UUPSUpgradeable.upgradeTo.selector,
            associatedFunction: ownerUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[6] = ManifestAssociatedFunction({
            executionSelector: UUPSUpgradeable.upgradeToAndCall.selector,
            associatedFunction: ownerUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[7] = ManifestAssociatedFunction({
            executionSelector: this.setSigner.selector,
            associatedFunction: ownerUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[8] = ManifestAssociatedFunction({
            executionSelector: this.setRecoveryAddress.selector,
            associatedFunction: ownerUserOpValidationFunction
        });

        ManifestFunction memory ownerOrSelfRuntimeValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.SELF,
            functionId: uint8(FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF),
            dependencyIndex: 0 // Unused.
        });
        ManifestFunction memory ownerSignerOrSelfRuntimeValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.SELF,
            functionId: uint8(FunctionId.RUNTIME_VALIDATION_OWNER_SIGNER_OR_SELF),
            dependencyIndex: 0 // Unused.
        });
        ManifestFunction memory recoveryRuntimeValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.SELF,
            functionId: uint8(FunctionId.RUNTIME_VALIDATION_RECOVERY),
            dependencyIndex: 0 // Unused.
        });
        ManifestFunction memory alwaysAllowFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW,
            functionId: 0, // Unused.
            dependencyIndex: 0 // Unused.
        });

        manifest.runtimeValidationFunctions = new ManifestAssociatedFunction[](15);
        manifest.runtimeValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.transferOwnership.selector,
            associatedFunction: ownerOrSelfRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[1] = ManifestAssociatedFunction({
            executionSelector: this.owner.selector,
            associatedFunction: alwaysAllowFunction
        });
        manifest.runtimeValidationFunctions[2] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.execute.selector,
            associatedFunction: ownerSignerOrSelfRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[3] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.executeBatch.selector,
            associatedFunction: ownerSignerOrSelfRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[4] = ManifestAssociatedFunction({
            executionSelector: IPluginManager.installPlugin.selector,
            associatedFunction: ownerOrSelfRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[5] = ManifestAssociatedFunction({
            executionSelector: IPluginManager.uninstallPlugin.selector,
            associatedFunction: ownerOrSelfRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[6] = ManifestAssociatedFunction({
            executionSelector: UUPSUpgradeable.upgradeTo.selector,
            associatedFunction: ownerOrSelfRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[7] = ManifestAssociatedFunction({
            executionSelector: UUPSUpgradeable.upgradeToAndCall.selector,
            associatedFunction: ownerOrSelfRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[8] = ManifestAssociatedFunction({
            executionSelector: this.isValidSignature.selector,
            associatedFunction: alwaysAllowFunction
        });
        manifest.runtimeValidationFunctions[9] = ManifestAssociatedFunction({
            executionSelector: this.setSigner.selector,
            associatedFunction: ownerOrSelfRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[10] = ManifestAssociatedFunction({
            executionSelector: this.setRecoveryAddress.selector,
            associatedFunction: ownerOrSelfRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[11] = ManifestAssociatedFunction({
            executionSelector: this.recoveryAddress.selector,
            associatedFunction: alwaysAllowFunction
        });
        manifest.runtimeValidationFunctions[12] = ManifestAssociatedFunction({
            executionSelector: this.signersLength.selector,
            associatedFunction: alwaysAllowFunction
        });
        manifest.runtimeValidationFunctions[13] = ManifestAssociatedFunction({
            executionSelector: this.signers.selector,
            associatedFunction: alwaysAllowFunction
        });
        manifest.runtimeValidationFunctions[14] = ManifestAssociatedFunction({
            executionSelector: this.recoverOwner.selector,
            associatedFunction: recoveryRuntimeValidationFunction
        });
        return manifest;
    }

    // ┏━━━━━━━━━━━━━━━┓
    // ┃    EIP-165    ┃
    // ┗━━━━━━━━━━━━━━━┛

    /// @inheritdoc BasePlugin
    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
        return interfaceId == type(IMultiSignerPlugin).interfaceId || super.supportsInterface(interfaceId);
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Internal / Private functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function _transferOwnership(address newOwner) internal {
        address previousOwner = _infos[msg.sender].owner;
        _infos[msg.sender].owner = newOwner;
        emit OwnershipTransferred(msg.sender, previousOwner, newOwner);
    }
}