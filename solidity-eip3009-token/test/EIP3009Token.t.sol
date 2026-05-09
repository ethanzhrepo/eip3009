// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {EIP3009Token} from "../src/EIP3009Token.sol";

contract EIP3009TokenTest is Test {
    EIP3009Token internal token;

    uint256 internal authorizerKey = 0xA11CE;
    address internal authorizer;
    address internal recipient = address(0xB0B);
    address internal relayer = address(0xCAFE);

    function setUp() public {
        authorizer = vm.addr(authorizerKey);
        token = new EIP3009Token("Example USD", "xUSD", "1", 6, address(this));
        token.mint(authorizer, 1_000_000_000);
        vm.warp(1_700_000_000);
    }

    function testTypeHashesMatchEIP3009() public view {
        assertEq(
            token.TRANSFER_WITH_AUTHORIZATION_TYPEHASH(),
            keccak256(
                "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
            )
        );
        assertEq(
            token.RECEIVE_WITH_AUTHORIZATION_TYPEHASH(),
            keccak256(
                "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
            )
        );
        assertEq(
            token.CANCEL_AUTHORIZATION_TYPEHASH(), keccak256("CancelAuthorization(address authorizer,bytes32 nonce)")
        );
    }

    function testTransferWithAuthorizationMovesTokensAndConsumesNonce() public {
        bytes32 nonce = keccak256("transfer nonce");
        uint256 value = 100_000_000;
        (uint8 v, bytes32 r, bytes32 s) =
            signTransfer(authorizerKey, recipient, value, 1_699_999_999, 1_700_000_100, nonce);

        vm.prank(relayer);
        token.transferWithAuthorization(authorizer, recipient, value, 1_699_999_999, 1_700_000_100, nonce, v, r, s);

        assertEq(token.balanceOf(authorizer), 900_000_000);
        assertEq(token.balanceOf(recipient), value);
        assertTrue(token.authorizationState(authorizer, nonce));
    }

    function testTransferWithAuthorizationRejectsReplay() public {
        bytes32 nonce = keccak256("replay nonce");
        uint256 value = 100_000_000;
        (uint8 v, bytes32 r, bytes32 s) =
            signTransfer(authorizerKey, recipient, value, 1_699_999_999, 1_700_000_100, nonce);

        token.transferWithAuthorization(authorizer, recipient, value, 1_699_999_999, 1_700_000_100, nonce, v, r, s);

        vm.expectRevert(abi.encodeWithSelector(EIP3009Token.AuthorizationAlreadyUsed.selector, authorizer, nonce));
        token.transferWithAuthorization(authorizer, recipient, value, 1_699_999_999, 1_700_000_100, nonce, v, r, s);
    }

    function testReceiveWithAuthorizationMustBeSubmittedByRecipient() public {
        bytes32 nonce = keccak256("receive nonce");
        uint256 value = 100_000_000;
        (uint8 v, bytes32 r, bytes32 s) =
            signReceive(authorizerKey, recipient, value, 1_699_999_999, 1_700_000_100, nonce);

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(EIP3009Token.CallerMustBePayee.selector, relayer, recipient));
        token.receiveWithAuthorization(authorizer, recipient, value, 1_699_999_999, 1_700_000_100, nonce, v, r, s);

        vm.prank(recipient);
        token.receiveWithAuthorization(authorizer, recipient, value, 1_699_999_999, 1_700_000_100, nonce, v, r, s);

        assertEq(token.balanceOf(recipient), value);
        assertTrue(token.authorizationState(authorizer, nonce));
    }

    function testCancelAuthorizationConsumesNonceAndBlocksTransfer() public {
        bytes32 nonce = keccak256("cancel nonce");
        (uint8 cancelV, bytes32 cancelR, bytes32 cancelS) = signCancel(authorizerKey, nonce);

        vm.prank(relayer);
        token.cancelAuthorization(authorizer, nonce, cancelV, cancelR, cancelS);

        assertTrue(token.authorizationState(authorizer, nonce));

        uint256 value = 100_000_000;
        (uint8 v, bytes32 r, bytes32 s) =
            signTransfer(authorizerKey, recipient, value, 1_699_999_999, 1_700_000_100, nonce);
        vm.expectRevert(abi.encodeWithSelector(EIP3009Token.AuthorizationAlreadyUsed.selector, authorizer, nonce));
        token.transferWithAuthorization(authorizer, recipient, value, 1_699_999_999, 1_700_000_100, nonce, v, r, s);
    }

    function testRejectsAuthorizationOutsideTimeWindow() public {
        bytes32 futureNonce = keccak256("future nonce");
        (uint8 futureV, bytes32 futureR, bytes32 futureS) =
            signTransfer(authorizerKey, recipient, 1, 1_700_000_001, 1_700_000_100, futureNonce);

        vm.expectRevert(
            abi.encodeWithSelector(EIP3009Token.AuthorizationNotYetValid.selector, 1_700_000_000, 1_700_000_001)
        );
        token.transferWithAuthorization(
            authorizer, recipient, 1, 1_700_000_001, 1_700_000_100, futureNonce, futureV, futureR, futureS
        );

        bytes32 expiredNonce = keccak256("expired nonce");
        (uint8 expiredV, bytes32 expiredR, bytes32 expiredS) =
            signTransfer(authorizerKey, recipient, 1, 1_699_999_900, 1_700_000_000, expiredNonce);

        vm.expectRevert(
            abi.encodeWithSelector(EIP3009Token.AuthorizationExpired.selector, 1_700_000_000, 1_700_000_000)
        );
        token.transferWithAuthorization(
            authorizer, recipient, 1, 1_699_999_900, 1_700_000_000, expiredNonce, expiredV, expiredR, expiredS
        );
    }

    function signTransfer(
        uint256 privateKey,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce
    ) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        return vm.sign(
            privateKey,
            typedDataHash(
                keccak256(
                    abi.encode(
                        token.TRANSFER_WITH_AUTHORIZATION_TYPEHASH(),
                        authorizer,
                        to,
                        value,
                        validAfter,
                        validBefore,
                        nonce
                    )
                )
            )
        );
    }

    function signReceive(
        uint256 privateKey,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce
    ) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        return vm.sign(
            privateKey,
            typedDataHash(
                keccak256(
                    abi.encode(
                        token.RECEIVE_WITH_AUTHORIZATION_TYPEHASH(),
                        authorizer,
                        to,
                        value,
                        validAfter,
                        validBefore,
                        nonce
                    )
                )
            )
        );
    }

    function signCancel(uint256 privateKey, bytes32 nonce) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        return vm.sign(
            privateKey, typedDataHash(keccak256(abi.encode(token.CANCEL_AUTHORIZATION_TYPEHASH(), authorizer, nonce)))
        );
    }

    function typedDataHash(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), structHash));
    }
}
