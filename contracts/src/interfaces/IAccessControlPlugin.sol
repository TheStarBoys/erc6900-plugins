// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

interface IAccessControlPlugin {
    error NoRole();
    error NotAuthorized();

    event RoleAdminChanged(
        address indexed account,
        bytes32 indexed role,
        bytes32 previousAdminRole,
        bytes32 newAdminRole
    );

    event RoleGranted(
        address indexed account,
        bytes32 indexed role,
        address indexed roleTo
    );

    event RoleRevoked(
        address indexed account,
        bytes32 indexed role,
        address indexed roleTo
    );

    enum FunctionId {
        RUNTIME_VALIDATION_ADMIN_OR_SELF,
        RUNTIME_VALIDATION_SIGNER_OR_SELF,
        USER_OP_VALIDATION_ADMIN,
        USER_OP_VALIDATION_SIGNER
    }

    struct Access {
        address target;
        bytes4 selector;
        bool enable;
    }

    struct RoleData {
        EnumerableSet.AddressSet members;
        bool stopped; // Simply reports the role which has been stopped.
        bool permitAll;
        mapping(address => mapping(bytes4 => bool)) canAccess; // target => selector
        bytes32 adminRole;
    }

    function hasRole(bytes32 role, address sender) external view returns (bool);

    function grantRole(bytes32 role, address account) external;

    function revokeRole(bytes32 role, address account) external;

    function canSignMessages(address sender) external view returns(bool);

    function canAccess(address sender, address target, bytes4 selector) external view returns(bool);
}