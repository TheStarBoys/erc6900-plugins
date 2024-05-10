// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/utils/Strings.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {BasePlugin} from "@erc6900/reference-implementation/plugins/BasePlugin.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {UserOperation} from "@eth-infinitism/account-abstraction/interfaces/UserOperation.sol";
import {IStandardExecutor} from "@erc6900/reference-implementation/interfaces/IStandardExecutor.sol";
import {IPluginManager} from "@erc6900/reference-implementation/interfaces/IPluginManager.sol";
import {
    ManifestFunction,
    ManifestAssociatedFunctionType,
    ManifestAssociatedFunction,
    PluginManifest,
    ManifestExecutionFunction
} from "@erc6900/reference-implementation/interfaces/IPlugin.sol";

import {IAccessControlPlugin} from "contracts/src/interfaces/IAccessControlPlugin.sol";

contract AccessControlPlugin is BasePlugin, IAccessControlPlugin, IERC1271 {
    using ECDSA for bytes32;
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using EnumerableSet for EnumerableSet.AddressSet;

    string public constant NAME = "Access Control Plugin";
    string public constant VERSION = "1.0.0";
    string public constant AUTHOR = "Ivan Zhang";

    uint256 internal constant _SIG_VALIDATION_PASSED = 0;
    uint256 internal constant _SIG_VALIDATION_FAILED = 1;

    // bytes4(keccak256("isValidSignature(bytes32,bytes)"))
    bytes4 internal constant _1271_MAGIC_VALUE = 0x1626ba7e;

    mapping(address => EnumerableSet.Bytes32Set) private __roles;
    mapping(address => mapping(bytes32 => RoleData)) private _roleDatas; // MSCA => Role => RoleData
    mapping(address => mapping(address => bytes32)) private __toRole; // MSCA => EOA/SC => Role

    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;

    // the role that can only sign messages.
    bytes32 public constant SIGNER_ROLE = keccak256("SIGNER_ROLE");
    mapping(address => EnumerableSet.AddressSet) private __signers;

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Execution functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
    
    /// @inheritdoc IERC1271
    /// @dev The signature is valid if it is signed by the signers' private key
    /// (if the signer is an EOA) or if it is a valid ERC-1271 signature from the
    /// signer (if the signer is a contract). Note that unlike the signature
    /// validation used in `validateUserOp`, this does///*not** wrap the digest in
    /// an "Ethereum Signed Message" envelope before checking the signature in
    /// the EOA-owner case.
    function isValidSignature(bytes32 digest, bytes memory signature) public view override returns (bytes4) {
        EnumerableSet.AddressSet storage signers = _signers();

        uint length = signers.length();
        for (uint i; i < length;) {
            address signer = signers.at(i);
            if (SignatureChecker.isValidSignatureNow(signer, digest, signature)) {
                return _1271_MAGIC_VALUE;
            }
            unchecked {
                ++i;
            }
        }

        return 0xffffffff;
    }

    function grantRole(bytes32 role, address account) public virtual {
        _grantRole(role, account);
    }

    function revokeRole(bytes32 role, address account) public virtual {
        _revokeRole(role, account);
    }

    // TODO: Implemented in another plugin.
    // sender must be one of admins and there's two admins at least.
    // require(account != sender)
    // it will need a delay to call it again to actually revoke the admin privilege of `account`.
    function revokeAdmin(address account) public virtual {

    }

    function setRolePermitAll(bytes32 role, bool permitAll) public virtual {
        _getRoleData(role).permitAll = permitAll;
    }

    function setRoleStopped(bytes32 role, bool stopped) public virtual {
        _getRoleData(role).stopped = stopped;
    }

    function setRoleAccess(bytes32 role, address target, bytes4 selector, bool enable) public virtual {
        RoleData storage data = _getRoleData(role);
        data.canAccess[target][selector] = enable;
    }

    function setRoleAccessBatch(bytes32 role, Access[] memory acceses) public virtual {
        RoleData storage data = _getRoleData(role);
        uint length = acceses.length;
        for (uint i; i < length;) {
            Access memory access = acceses[i];
            data.canAccess[access.target][access.selector] = access.enable;
            unchecked {
                ++i;
            }
        }
    }

    function checkAccess(address sender, address target, bytes4 selector) public view virtual {
        if (!canAccess(sender, target, selector)) {
            revert(
                string(
                    abi.encodePacked(
                        "AccessControlPlugin: account=",
                        Strings.toHexString(_msca()),
                        ",sender=",
                        Strings.toHexString(sender),
                        " has no access to target=",
                        Strings.toHexString(target),
                        " selector="
                        // Strings.toHexString(target), // TODO
                    )
                )
            );
        }
    }


    function canAccess(address sender, address target, bytes4 selector) public view virtual returns(bool) {
        RoleData storage senderRole = _senderRole(sender);

        return !senderRole.stopped && (
            senderRole.permitAll || senderRole.canAccess[target][selector]);
    }

    function canSignMessages(address sender) public view virtual returns(bool) {
        return _signers().contains(sender);
    }

    function getRoleAdmin(bytes32 role) public view virtual returns (bytes32) {
        return _getRoleData(role).adminRole;
    }

    function hasRole(bytes32 role, address sender) public view virtual override returns (bool) {
        return _roleDatas[_msca()][role].members.contains(sender);
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin view functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛


    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc BasePlugin
    function onInstall(bytes calldata data) external override {
        address[] memory admins = abi.decode(data, (address[]));
        uint length = admins.length;
        for (uint i; i < length;) {
            _grantRole(DEFAULT_ADMIN_ROLE, admins[i]);
            unchecked {
                ++i;
            }
        }
    }

    /// @inheritdoc BasePlugin
    function onUninstall(bytes calldata) external override {
        // If we clear too many states on uninstall, it'll become
        // vulnerable to get hacked. e.g. a large loop.
        // Even if we dont clear any states, it's OK.
        // So we just clear necessary states.
        
        // TODO: determine what state needs to clear.

        // Remove signers
        // EnumerableSet.AddressSet storage signers = _signers();
        // uint length = signers.length();
        // for (uint i; i < length;) {
        //     signers.remove(signers.at(i));

        //     unchecked {
        //         ++i;
        //     }
        // }

        // Remove Admins
        // RoleData storage data = _getRoleData(DEFAULT_ADMIN_ROLE);
        // length = data.members.length();
        // for (uint i; i < length;) {
        //     revokeRole(DEFAULT_ADMIN_ROLE, data.members.at(i));
        //     unchecked {
        //         ++i;
        //     }
        // }

        // It's hard to remove all role datas so that
        // we just mark the role as stopped.
        // EnumerableSet.Bytes32Set storage roles = _roles();
        // length = roles.length();
        // for (uint i; i < length;) {
        //     bytes32 role = roles.at(i);
        //     _getRoleData(role).stopped = true;
        //     unchecked {
        //         ++i;
        //     }
        // }
    }

    /// @inheritdoc BasePlugin
    function runtimeValidationFunction(uint8 functionId, address sender, uint256, bytes calldata)
        external
        view
        override
    {
        if (functionId == uint8(FunctionId.RUNTIME_VALIDATION_SIGNER_OR_SELF)) {
            if (hasRole(DEFAULT_ADMIN_ROLE, sender)) {
                return;
            }

            if (sender == msg.sender) {
                return;
            }

            // Validate that the sender is the signer of the account or self.
            bool canSign = canSignMessages(sender);

            if (!canSign) {
                revert NotAuthorized();
            }

            RoleData storage data = _senderRole(sender);
            // TODO: Permissions check
            if (!data.permitAll) {
                revert NotAuthorized();
            }

            return;
        } else if (functionId == uint8(FunctionId.RUNTIME_VALIDATION_ADMIN_OR_SELF)) {
            if (sender != msg.sender && !hasRole(DEFAULT_ADMIN_ROLE, sender)) {
                revert NotAuthorized();
            }

            return;
        }
        revert NotImplemented();
    }

    /// @inheritdoc BasePlugin
    function userOpValidationFunction(uint8 functionId, UserOperation calldata userOp, bytes32 userOpHash)
        external
        view
        override
        returns (uint256)
    {
        if (functionId == uint8(FunctionId.USER_OP_VALIDATION_SIGNER)) {
            // Validate the user op signature against the owner.
            (address signer,) = (userOpHash.toEthSignedMessageHash()).tryRecover(userOp.signature);

            if (signer == address(0) || !canSignMessages(signer)) {
                return _SIG_VALIDATION_FAILED;
            }

            if (hasRole(DEFAULT_ADMIN_ROLE, signer)) {
                return _SIG_VALIDATION_PASSED;
            }

            // Permissions check
            RoleData storage rd = _senderRole(signer);

            if (!rd.permitAll) {
                return _SIG_VALIDATION_FAILED;
            }

            return _SIG_VALIDATION_PASSED;
        } else if (functionId == uint8(FunctionId.USER_OP_VALIDATION_ADMIN)) {
            (address signer,) = (userOpHash.toEthSignedMessageHash()).tryRecover(userOp.signature);
            if (signer == address(0) || !hasRole(DEFAULT_ADMIN_ROLE, signer)) {
                return _SIG_VALIDATION_FAILED;
            }

            return _SIG_VALIDATION_PASSED;
        }

        revert NotImplemented();
    }

    /// @inheritdoc BasePlugin
    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.name = NAME;
        manifest.version = VERSION;
        manifest.author = AUTHOR;

        string[] memory adminPermissions = new string[](1);
        adminPermissions[0] = "Access Control";

        ////// Configure `Execution` Functions
        manifest.executionFunctions = new ManifestExecutionFunction[](12);
        manifest.executionFunctions[0] =
            ManifestExecutionFunction(this.grantRole.selector, adminPermissions);
        manifest.executionFunctions[1] =
            ManifestExecutionFunction(this.revokeRole.selector, adminPermissions);
        manifest.executionFunctions[2] =
            ManifestExecutionFunction(this.setRolePermitAll.selector, adminPermissions);
        manifest.executionFunctions[3] =
            ManifestExecutionFunction(this.setRoleStopped.selector, adminPermissions);
        manifest.executionFunctions[4] =
            ManifestExecutionFunction(this.setRoleAccess.selector, adminPermissions);
        manifest.executionFunctions[5] =
            ManifestExecutionFunction(this.setRoleAccessBatch.selector, adminPermissions);
        
        manifest.executionFunctions[6] = ManifestExecutionFunction(this.isValidSignature.selector, new string[](0));
        manifest.executionFunctions[7] = ManifestExecutionFunction(this.checkAccess.selector, new string[](0));
        manifest.executionFunctions[8] = ManifestExecutionFunction(this.canAccess.selector, new string[](0));
        manifest.executionFunctions[9] = ManifestExecutionFunction(this.canSignMessages.selector, new string[](0));
        manifest.executionFunctions[10] = ManifestExecutionFunction(this.getRoleAdmin.selector, new string[](0));
        manifest.executionFunctions[11] = ManifestExecutionFunction(this.hasRole.selector, new string[](0));

        ////// Configure `UserOperation Validation` Functions
        ManifestFunction memory adminUserOpValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.SELF,
            functionId: uint8(FunctionId.USER_OP_VALIDATION_ADMIN),
            dependencyIndex: 0 // Unused.
        });
        ManifestFunction memory signerUserOpValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.SELF,
            functionId: uint8(FunctionId.USER_OP_VALIDATION_SIGNER),
            dependencyIndex: 0 // Unused.
        });

        // Validates Admin
        manifest.userOpValidationFunctions = new ManifestAssociatedFunction[](12);
        manifest.userOpValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.grantRole.selector,
            associatedFunction: adminUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[1] = ManifestAssociatedFunction({
            executionSelector: this.revokeRole.selector,
            associatedFunction: adminUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[2] = ManifestAssociatedFunction({
            executionSelector: this.setRolePermitAll.selector,
            associatedFunction: adminUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[3] = ManifestAssociatedFunction({
            executionSelector: this.setRoleStopped.selector,
            associatedFunction: adminUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[4] = ManifestAssociatedFunction({
            executionSelector: this.setRoleAccess.selector,
            associatedFunction: adminUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[5] = ManifestAssociatedFunction({
            executionSelector: this.setRoleAccessBatch.selector,
            associatedFunction: adminUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[6] = ManifestAssociatedFunction({
            executionSelector: IPluginManager.installPlugin.selector,
            associatedFunction: adminUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[7] = ManifestAssociatedFunction({
            executionSelector: IPluginManager.uninstallPlugin.selector,
            associatedFunction: adminUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[8] = ManifestAssociatedFunction({
            executionSelector: UUPSUpgradeable.upgradeTo.selector,
            associatedFunction: adminUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[9] = ManifestAssociatedFunction({
            executionSelector: UUPSUpgradeable.upgradeToAndCall.selector,
            associatedFunction: adminUserOpValidationFunction
        });

        // Validates Signer
        manifest.userOpValidationFunctions[10] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.execute.selector,
            associatedFunction: signerUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[11] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.executeBatch.selector,
            associatedFunction: signerUserOpValidationFunction
        });
        
        ////// Configure `Runtime Validation` Functions
        ManifestFunction memory adminOrSelfRuntimeValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.SELF,
            functionId: uint8(FunctionId.RUNTIME_VALIDATION_ADMIN_OR_SELF),
            dependencyIndex: 0 // Unused.
        });
        ManifestFunction memory signerOrSelfRuntimeValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.SELF,
            functionId: uint8(FunctionId.RUNTIME_VALIDATION_SIGNER_OR_SELF),
            dependencyIndex: 0 // Unused.
        });
        ManifestFunction memory alwaysAllowFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW,
            functionId: 0, // Unused.
            dependencyIndex: 0 // Unused.
        });
        manifest.runtimeValidationFunctions = new ManifestAssociatedFunction[](18);
        // Validates Admin or Self
        manifest.runtimeValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.grantRole.selector,
            associatedFunction: adminOrSelfRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[1] = ManifestAssociatedFunction({
            executionSelector: this.revokeRole.selector,
            associatedFunction: adminOrSelfRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[2] = ManifestAssociatedFunction({
            executionSelector: this.setRolePermitAll.selector,
            associatedFunction: adminOrSelfRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[3] = ManifestAssociatedFunction({
            executionSelector: this.setRoleStopped.selector,
            associatedFunction: adminOrSelfRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[4] = ManifestAssociatedFunction({
            executionSelector: this.setRoleAccess.selector,
            associatedFunction: adminOrSelfRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[5] = ManifestAssociatedFunction({
            executionSelector: this.setRoleAccessBatch.selector,
            associatedFunction: adminOrSelfRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[6] = ManifestAssociatedFunction({
            executionSelector: IPluginManager.installPlugin.selector,
            associatedFunction: adminOrSelfRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[7] = ManifestAssociatedFunction({
            executionSelector: IPluginManager.uninstallPlugin.selector,
            associatedFunction: adminOrSelfRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[8] = ManifestAssociatedFunction({
            executionSelector: UUPSUpgradeable.upgradeTo.selector,
            associatedFunction: adminOrSelfRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[9] = ManifestAssociatedFunction({
            executionSelector: UUPSUpgradeable.upgradeToAndCall.selector,
            associatedFunction: adminOrSelfRuntimeValidationFunction
        });

        // Validates Signer or Self
        manifest.runtimeValidationFunctions[10] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.execute.selector,
            associatedFunction: signerOrSelfRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[11] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.executeBatch.selector,
            associatedFunction: signerOrSelfRuntimeValidationFunction
        });

        // Always Allow
        manifest.runtimeValidationFunctions[12] = ManifestAssociatedFunction({
            executionSelector: this.isValidSignature.selector,
            associatedFunction: alwaysAllowFunction
        });
        manifest.runtimeValidationFunctions[13] = ManifestAssociatedFunction({
            executionSelector: this.checkAccess.selector,
            associatedFunction: alwaysAllowFunction
        });
        manifest.runtimeValidationFunctions[14] = ManifestAssociatedFunction({
            executionSelector: this.canAccess.selector,
            associatedFunction: alwaysAllowFunction
        });
        manifest.runtimeValidationFunctions[15] = ManifestAssociatedFunction({
            executionSelector: this.canSignMessages.selector,
            associatedFunction: alwaysAllowFunction
        });
        manifest.runtimeValidationFunctions[16] = ManifestAssociatedFunction({
            executionSelector: this.getRoleAdmin.selector,
            associatedFunction: alwaysAllowFunction
        });
        manifest.runtimeValidationFunctions[17] = ManifestAssociatedFunction({
            executionSelector: this.hasRole.selector,
            associatedFunction: alwaysAllowFunction
        });

        return manifest;
    }

    // ┏━━━━━━━━━━━━━━━┓
    // ┃    EIP-165    ┃
    // ┗━━━━━━━━━━━━━━━┛

    /// @inheritdoc BasePlugin
    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Internal / Private functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛


    function _grantRole(bytes32 role, address account) internal virtual {
        if (!hasRole(role, account)) {
            RoleData storage data = _getRoleData(role);
            data.members.add(account);
            __toRole[_msca()][account] = role;
            _signers().add(account);

            emit RoleGranted(_msca(), role, account);

            if (!_roles().contains(role)) {
                _roles().add(role);
            }
        }
    }

    function _revokeRole(bytes32 role, address account) internal virtual {
        if (hasRole(role, account)) {
            RoleData storage data = _getRoleData(role);
            data.members.remove(account);
            delete __toRole[_msca()][account];
            _signers().remove(account);

            emit RoleRevoked(_msca(), role, account);
        }
    }

    function setRoleAdmin(bytes32 role, bytes32 adminRole) internal virtual {
        bytes32 previousAdminRole = getRoleAdmin(role);
        _getRoleData(role).adminRole = adminRole;
        emit RoleAdminChanged(_msca(), role, previousAdminRole, adminRole);
    }

    function _senderRole(address sender) internal view returns(RoleData storage data) {
        bytes32 role = _toRole(sender);
        data = _getRoleData(role);

        if (role == DEFAULT_ADMIN_ROLE && !data.members.contains(sender)) { revert NoRole(); }
    }

    function _toRole(address sender) internal view returns(bytes32) {
        return __toRole[_msca()][sender];
    }

    function _getRoleData(bytes32 role) internal view returns(RoleData storage) {
        return  _roleDatas[_msca()][role];
    }

    function _roles() internal view returns(EnumerableSet.Bytes32Set storage) {
        return __roles[_msca()];
    }

    function _signers() internal view returns(EnumerableSet.AddressSet storage) {
        return __signers[_msca()];
    }

    // Treats msg.sender as an MSCA.
    function _msca() internal view returns(address) {
        return msg.sender;
    }
}