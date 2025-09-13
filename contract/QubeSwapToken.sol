// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title QubeSwap Token -v3
 * @author Mabble Protocol (@muroko)
 * @notice QST is a multi-chain token
 * @dev A custom ERC-20 token with EIP-2612 permit functionality.
 * This token contract includes additional features such as trading status management,
 * ownership transfer with timelock, and the ability to recover stuck native tokens * * and other tokens.
 * @custom:security-contact security@mabble.io
 * Website: qubeswap.com
 */
contract QubeSwapToken {
	using ECDSA for bytes32;
    // --- Events ---
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event TradingStatusUpdated(bool indexed liveTrading);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event StuckNativeRemoved(uint256 amount, address indexed recipient);
    event StuckTokenRemoved(address indexed token, uint256 amount, address indexed recipient);

    // --- Constants ---
    string public constant name = "QubeSwapToken";
    string public constant symbol = "QST";
    uint8 public constant decimals = 18;
    uint256 public constant MAX_SUPPLY = 100_000_000 * 10**18; // 100M tokens

    // --- Storage ---
    uint256 public totalSupply;
    uint256 public constant TIMELOCK_DURATION = 48 hours;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => uint256) public nonces;
    mapping(address => bool) public recoverableTokens;
    mapping(bytes32 => uint256) public queuedTransactions;

    address public owner;
    bool public liveTrading = true;

    // EIP-2612 Permit
    bytes32 private constant PERMIT_TYPEHASH =
        keccak256("Permit(address tokenOwner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    bytes32 private immutable DOMAIN_SEPARATOR;

    // --- Constructor ---
    constructor() {
        owner = msg.sender;
        balanceOf[owner] = MAX_SUPPLY;
        totalSupply = MAX_SUPPLY;

        DOMAIN_SEPARATOR = _computeDomainSeparator();
    }

    // --- Core Functions ---
    function transfer(address to, uint256 amount) public returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) public returns (bool) {
        uint256 currentAllowance = allowance[from][msg.sender];
        require(currentAllowance >= amount, "ERC20: transfer amount exceeds allowance");

        allowance[from][msg.sender] = currentAllowance - amount;
        _transfer(from, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) public returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function increaseAllowance(address spender, uint256 addedValue) public returns (bool) {
        allowance[msg.sender][spender] += addedValue;
        emit Approval(msg.sender, spender, allowance[msg.sender][spender]);
        return true;
    }

    function decreaseAllowance(address spender, uint256 subtractedValue) public returns (bool) {
        uint256 currentAllowance = allowance[msg.sender][spender];
        require(currentAllowance >= subtractedValue, "ERC20: decreased allowance below zero");

        allowance[msg.sender][spender] = currentAllowance - subtractedValue;
        emit Approval(msg.sender, spender, allowance[msg.sender][spender]);
        return true;
    }

    // --- Permit (EIP-2612) ---
    function permit(
        address tokenOwner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public {
        require(block.timestamp <= deadline, "ERC20Permit: expired deadline");

        bytes32 structHash = keccak256(
            abi.encode(
                PERMIT_TYPEHASH,
                tokenOwner,
                spender,
                value,
                nonces[tokenOwner]++,
                deadline
            )
        );

        bytes32 hash = keccak256(abi.encode(uint16(0x1901), DOMAIN_SEPARATOR, structHash));
        address signer = ECDSA.recover(hash, v, r, s);
        require(signer == tokenOwner, "ERC20Permit: invalid signature");

        allowance[tokenOwner][spender] = value;
        emit Approval(tokenOwner, spender, value);
    }

    // --- Admin Functions ---
    function queueTradeable(bool _status) external isOwner {
        bytes32 txHash = keccak256(abi.encodePacked("tradeable", _status));
        queuedTransactions[txHash] = block.timestamp + TIMELOCK_DURATION;
    }

    function executeTradeable(bool _status) external isOwner {
        bytes32 txHash = keccak256(abi.encodePacked("tradeable", _status));
        require(queuedTransactions[txHash] > 0, "Transaction not queued or already executed");
        require(block.timestamp >= queuedTransactions[txHash], "Timelock not expired");
        delete queuedTransactions[txHash];
        tradeable(_status);
    }

    function tradeable(bool _status) public isOwner {
        liveTrading = _status;
        emit TradingStatusUpdated(_status);
    }

    function transferOwnership(address newOwner) public isOwner {
        require(newOwner != address(0), "Ownable: new owner is zero address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function removeStuckNative(uint256 amount) public isOwner {
        payable(owner).transfer(amount);
        emit StuckNativeRemoved(amount, owner);
    }

    function setRecoverableToken(address token, bool allowed) external isOwner {
        recoverableTokens[token] = allowed;
    }

    function removeStuckToken(address token, uint256 amount) external isOwner {
        require(recoverableTokens[token], "Not recoverable");
        IERC20(token).transfer(owner, amount);
        emit StuckTokenRemoved(token, amount, owner);
    }

    // --- Internal Functions ---
    function _transfer(
        address from,
        address to,
        uint256 amount
    ) internal {
        require(to != address(0), "ERC20: transfer to zero address");
        require(balanceOf[from] >= amount, "ERC20: transfer amount exceeds balance");

        // Trading restriction (owner can always transfer)
        require(liveTrading || msg.sender == owner, "QST: trading is disabled");

        unchecked {
            balanceOf[from] -= amount;
            balanceOf[to] += amount;
        }

        emit Transfer(from, to, amount);
    }

    function _computeDomainSeparator() private view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                    keccak256(bytes(name)),
                    keccak256("1"),
                    block.chainid,
                    address(this)
                )
            );
    }

    // --- Modifier ---
    modifier isOwner() {
        require(msg.sender == owner, "Ownable: caller is not the owner");
        _;
    }
}

// Minimal ERC20 interface for recovery function
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}