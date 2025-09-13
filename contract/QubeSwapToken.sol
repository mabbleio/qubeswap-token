// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title QubeSwap Token - v3.2
 * @author Mabble Protocol (@muroko)
 * @notice QST is a multi-chain token
 * @dev A custom ERC-20 token with EIP-2612 permit functionality.
 * This token contract includes additional features such as trading status management,
 * ownership transfer with timelock, and the ability to recover stuck native tokens * * and other tokens.
 * @custom:security-contact security@mabble.io
 * Website: qubeswap.com
 */
contract QubeSwapToken is IERC20, ReentrancyGuard {
	using ECDSA for bytes32;
    using SafeERC20 for IERC20;

    // --- Events ---
    //event Transfer(address indexed from, address indexed to, uint256 value);
    //event Approval(address indexed owner, address indexed spender, uint256 value);
    event TradingStatusUpdated(bool indexed liveTrading);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event StuckNativeRemoved(uint256 amount, address indexed recipient);
    event StuckTokenRemoved(address indexed token, uint256 amount, address indexed recipient);
    event OwnerAdded(address indexed owner);
    event OwnerRemoved(address indexed owner);
    event StuckTokenRemoved(
    address indexed token,      // Token address
    address indexed recipient,  // Who received the tokens (e.g., owner)
    uint256 amount               // Amount recovered
);


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
    mapping(address => bool) private _recoverableTokens;
    mapping(bytes32 => uint256) public queuedTransactions;

    // Multi-owner state
    address[] public owners;
    mapping(address => bool) public isOwner;

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
        _addOwner(msg.sender); // Deployer is the first owner
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
    function queueTradeable(bool _status) external onlyOwner nonReentrant {
        bytes32 txHash = keccak256(abi.encodePacked("tradeable", _status));
        queuedTransactions[txHash] = block.timestamp + TIMELOCK_DURATION;
    }

    function executeTradeable(bool _status) external onlyOwner nonReentrant {
        bytes32 txHash = keccak256(abi.encodePacked("tradeable", _status));
        require(queuedTransactions[txHash] > 0, "Transaction not queued or already executed");
        require(block.timestamp >= queuedTransactions[txHash], "Timelock not expired");
        delete queuedTransactions[txHash];
        tradeable(_status);
    }

    function tradeable(bool _status) public onlyOwner {
        liveTrading = _status;
        emit TradingStatusUpdated(_status);
    }

    // Owner management
    function _addOwner(address _owner) internal {
        require(!isOwner[_owner], "Already an owner");
        owners.push(_owner);
        isOwner[_owner] = true;
        emit OwnerAdded(_owner);
    }

    function addOwner(address _owner) public onlyOwner {
        _addOwner(_owner);
    }

    function removeOwner(address _owner) public onlyOwner {
        require(_owner != msg.sender, "Cannot remove yourself");
        require(isOwner[_owner], "Not an owner");
        isOwner[_owner] = false;
        emit OwnerRemoved(_owner);
    }

    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is zero address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function removeStuckNative(uint256 amount) public onlyOwner {
        payable(owner).transfer(amount);
        emit StuckNativeRemoved(amount, owner);
    }

    function setRecoverableToken(address token, bool status) external onlyOwner nonReentrant {
        _recoverableTokens[token] = status;
    }

    function removeStuckToken(
       address tokenAddress,
       uint256 amount
    ) external onlyOwner nonReentrant {
        require(_recoverableTokens[tokenAddress], "Token not recoverable");
        IERC20(tokenAddress).safeTransfer(owner, amount);

        // Fix: Add the recipient (owner) as the 2nd argument
        emit StuckTokenRemoved(tokenAddress, owner, amount);
    }

    // --- Internal Functions ---
    function _transfer(
       address from,
       address to,
       uint256 amount
    ) internal virtual {
        require(from != address(0), "ERC20: transfer from the zero address");
        require(to != address(0), "ERC20: transfer to the zero address");

        // Cache the balance to avoid double read
        uint256 fromBalance = balanceOf[from];
        require(fromBalance >= amount, "ERC20: transfer amount exceeds balance");

        // Use cached value for the subtraction
        unchecked {
           balanceOf[from] = fromBalance - amount;
        }
           uint256 toBalance = balanceOf[to];
           balanceOf[to] = toBalance + amount;

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

    // Modifiers
    modifier onlyOwner() {
        require(isOwner[msg.sender], "Ownable: caller is not an owner");
        _;
    }
}

// Minimal ERC20 interface for recovery function
//interface IERC20 {
//    function transfer(address to, uint256 amount) external returns (bool);
//}