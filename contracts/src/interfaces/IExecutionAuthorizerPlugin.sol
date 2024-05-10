// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IExecutionAuthorizerPlugin {
    enum FunctionId {
        PRE_RUNTIME_VALIDATION_AUTH,
        PRE_USER_OP_VALIDATION_AUTH
    }

    error NotAuthorized();

    function setPermitCall(address target, bytes4 selector, bool enable) external;
}
