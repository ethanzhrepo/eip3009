// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC20} from "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import {Ownable} from "openzeppelin-contracts/contracts/access/Ownable.sol";
import {EIP712} from "openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

contract EIP3009Token is ERC20, EIP712, Ownable {
    bytes32 public constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH = keccak256(
        "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );
    bytes32 public constant RECEIVE_WITH_AUTHORIZATION_TYPEHASH = keccak256(
        "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );
    bytes32 public constant CANCEL_AUTHORIZATION_TYPEHASH =
        keccak256("CancelAuthorization(address authorizer,bytes32 nonce)");

    mapping(address authorizer => mapping(bytes32 nonce => bool usedOrCanceled)) public authorizationState;

    uint8 private immutable _tokenDecimals;
    string private _tokenVersion;

    event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce);
    event AuthorizationCanceled(address indexed authorizer, bytes32 indexed nonce);

    error AuthorizationAlreadyUsed(address authorizer, bytes32 nonce);
    error AuthorizationNotYetValid(uint256 currentTime, uint256 validAfter);
    error AuthorizationExpired(uint256 currentTime, uint256 validBefore);
    error InvalidSignature(address expectedSigner, address recoveredSigner);
    error CallerMustBePayee(address caller, address payee);

    constructor(
        string memory name_,
        string memory symbol_,
        string memory version_,
        uint8 decimals_,
        address initialOwner
    ) ERC20(name_, symbol_) EIP712(name_, version_) Ownable(initialOwner) {
        _tokenVersion = version_;
        _tokenDecimals = decimals_;
    }

    function decimals() public view override returns (uint8) {
        return _tokenDecimals;
    }

    function version() external view returns (string memory) {
        return _tokenVersion;
    }

    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    function mint(address to, uint256 value) external onlyOwner {
        _mint(to, value);
    }

    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        _useTransferAuthorization(
            TRANSFER_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce, v, r, s
        );
        _transfer(from, to, value);
    }

    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        if (_msgSender() != to) {
            revert CallerMustBePayee(_msgSender(), to);
        }
        _useTransferAuthorization(
            RECEIVE_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce, v, r, s
        );
        _transfer(from, to, value);
    }

    function cancelAuthorization(address authorizer, bytes32 nonce, uint8 v, bytes32 r, bytes32 s) external {
        _requireUnusedAuthorization(authorizer, nonce);
        bytes32 structHash = keccak256(abi.encode(CANCEL_AUTHORIZATION_TYPEHASH, authorizer, nonce));
        _requireValidSignature(authorizer, structHash, v, r, s);
        authorizationState[authorizer][nonce] = true;
        emit AuthorizationCanceled(authorizer, nonce);
    }

    function _useTransferAuthorization(
        bytes32 typeHash,
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal {
        _requireValidTime(validAfter, validBefore);
        _requireUnusedAuthorization(from, nonce);

        bytes32 structHash = keccak256(abi.encode(typeHash, from, to, value, validAfter, validBefore, nonce));
        _requireValidSignature(from, structHash, v, r, s);

        authorizationState[from][nonce] = true;
        emit AuthorizationUsed(from, nonce);
    }

    function _requireValidTime(uint256 validAfter, uint256 validBefore) internal view {
        if (block.timestamp <= validAfter) {
            revert AuthorizationNotYetValid(block.timestamp, validAfter);
        }
        if (block.timestamp >= validBefore) {
            revert AuthorizationExpired(block.timestamp, validBefore);
        }
    }

    function _requireUnusedAuthorization(address authorizer, bytes32 nonce) internal view {
        if (authorizationState[authorizer][nonce]) {
            revert AuthorizationAlreadyUsed(authorizer, nonce);
        }
    }

    function _requireValidSignature(address expectedSigner, bytes32 structHash, uint8 v, bytes32 r, bytes32 s)
        internal
        view
    {
        address recoveredSigner = ECDSA.recover(_hashTypedDataV4(structHash), v, r, s);
        if (recoveredSigner != expectedSigner) {
            revert InvalidSignature(expectedSigner, recoveredSigner);
        }
    }
}
