// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {IAccount} from "@eth-infinitism/account-abstraction/interfaces/IAccount.sol";
import "@erc6900/reference-implementation/interfaces/IPluginManager.sol";
import "@erc6900/reference-implementation/interfaces/IStandardExecutor.sol";
import "@erc6900/reference-implementation/interfaces/IPluginExecutor.sol";

interface IModularAccount is IAccount, IPluginManager, IStandardExecutor, IPluginExecutor {}