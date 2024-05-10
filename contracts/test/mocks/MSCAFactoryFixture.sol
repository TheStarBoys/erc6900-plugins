// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

import {UpgradeableModularAccount} from "@erc6900/reference-implementation/account/UpgradeableModularAccount.sol";
import "@erc6900/reference-implementation/interfaces/IPlugin.sol";
import "contracts/src/AccessControlPlugin.sol";
import "contracts/src/MultiSignerPlugin.sol";

/**
 * @title MSCAFactoryFixture
 * @dev a factory that initializes UpgradeableModularAccounts with a single accessControlPlugin,
 * intended for unit tests and local development, not for production.
 */
contract MSCAFactoryFixture {
    UpgradeableModularAccount public accountImplementation;
    IPlugin public accessControlPlugin = new AccessControlPlugin();
    IPlugin public multiSignerPlugin = new MultiSignerPlugin();

    bytes32 private immutable _PROXY_BYTECODE_HASH;

    uint32 public constant UNSTAKE_DELAY = 1 weeks;

    IEntryPoint public entryPoint;

    constructor(IEntryPoint _entryPoint) {
        entryPoint = _entryPoint;
        accountImplementation = new UpgradeableModularAccount(_entryPoint);
        _PROXY_BYTECODE_HASH = keccak256(
            abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(address(accountImplementation), ""))
        );
    }

    /**
     * create an account, and return its address.
     * returns the address even if the account is already deployed.
     * Note that during UserOperation execution, this method is called only if the account is not deployed.
     * This method returns an existing account address so that entryPoint.getSenderAddress() would work even after
     * account creation
     */
    function createAccountWithAccessControl(address admin, uint256 salt) public returns (UpgradeableModularAccount) {
        address addr = Create2.computeAddress(getSalt(admin, salt), _PROXY_BYTECODE_HASH);

        // short circuit if exists
        if (addr.code.length == 0) {
            address[] memory plugins = new address[](1);
            plugins[0] = address(accessControlPlugin);
            bytes32[] memory pluginManifestHashes = new bytes32[](1);
            pluginManifestHashes[0] = keccak256(abi.encode(accessControlPlugin.pluginManifest()));
            bytes[] memory pluginInitData = new bytes[](1);

            address[] memory admins = new address[](1);
            admins[0] = admin;
            pluginInitData[0] = abi.encode(admins);
            // not necessary to check return addr since next call will fail if so
            new ERC1967Proxy{salt: getSalt(admin, salt)}(address(accountImplementation), "");

            // point proxy to actual implementation and init plugins
            UpgradeableModularAccount(payable(addr)).initialize(plugins, pluginManifestHashes, pluginInitData);
        }

        return UpgradeableModularAccount(payable(addr));
    }

    function createAccountWithMultiSigner(address owner, uint256 salt) public returns (UpgradeableModularAccount) {
        address addr = Create2.computeAddress(getSalt(owner, salt), _PROXY_BYTECODE_HASH);

        // short circuit if exists
        if (addr.code.length == 0) {
            address[] memory plugins = new address[](1);
            plugins[0] = address(multiSignerPlugin);
            bytes32[] memory pluginManifestHashes = new bytes32[](1);
            pluginManifestHashes[0] = keccak256(abi.encode(multiSignerPlugin.pluginManifest()));
            bytes[] memory pluginInitData = new bytes[](1);

            pluginInitData[0] = abi.encode(owner);
            // not necessary to check return addr since next call will fail if so
            new ERC1967Proxy{salt: getSalt(owner, salt)}(address(accountImplementation), "");

            // point proxy to actual implementation and init plugins
            UpgradeableModularAccount(payable(addr)).initialize(plugins, pluginManifestHashes, pluginInitData);
        }

        return UpgradeableModularAccount(payable(addr));
    }

    /**
     * calculate the counterfactual address of this account as it would be returned by createAccountWithAccessControl()
     */
    function getAddress(address admin, uint256 salt) public view returns (address) {
        return Create2.computeAddress(getSalt(admin, salt), _PROXY_BYTECODE_HASH);
    }

    function addStake() external payable {
        entryPoint.addStake{value: msg.value}(UNSTAKE_DELAY);
    }

    function getSalt(address admin, uint256 salt) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(admin, salt));
    }
}
