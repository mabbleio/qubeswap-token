/**
      QST | a multi-chain token
        qubeswap.com
**/

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract QubeSwapToken {
  string public constant name = "QubeSwapToken";
  string public constant symbol = "QST";
  uint8 public constant decimals = 18;

  bool public liveTrading;
  address public owner;
  
  uint256 immutable public totalSupply;
  uint256 constant UINT256_MAX = type(uint256).max;
  uint256 public constant MAX_SUPPLY = 100000000 * 10 ** decimals; //100M

  mapping (address => uint) public nonces;
  mapping (address => uint256) public balanceOf;
  mapping (address => mapping(address => uint256)) public allowance;

  bytes32 public immutable DOMAIN_SEPARATOR;
  bytes32 public constant PERMIT_TYPEHASH = keccak256(
    "Permit(address owner,address spender,uint256 amount,uint256 nonce,uint256 deadline)"
  ); 


  event Transfer(address indexed from, address indexed to, uint256 amount);
  event Approval(address indexed owner, address indexed spender, uint256 amount);

  constructor() {
    liveTrading = true;
    owner = msg.sender;
    totalSupply = MAX_SUPPLY;

    DOMAIN_SEPARATOR = keccak256(
      abi.encode(
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
        keccak256(bytes(name)),
        keccak256(bytes("1")),
        block.chainid,
        address(this)
      )
    );

    unchecked {
      balanceOf[address(msg.sender)] = balanceOf[address(msg.sender)] + totalSupply;
    }

    emit Transfer(address(0), address(msg.sender), totalSupply);
  }

  function approve(address spender, uint256 amount) external returns (bool) {
    _approve(msg.sender, spender, amount);

    return true;
  }

  function increaseAllowance(address spender, uint256 addedValue) external returns (bool) {
    _approve(msg.sender, spender, allowance[msg.sender][spender] + addedValue);

    return true;
  }

  function decreaseAllowance(address spender, uint256 subtractedValue) external returns (bool) {
    _approve(msg.sender, spender, allowance[msg.sender][spender] - subtractedValue);

    return true;
  }

  function maxSupply() external pure returns (uint256) {
    return MAX_SUPPLY;
  }

  function transfer(address to, uint256 amount) external returns (bool) {
    _transfer(msg.sender, to, amount);

    return true;
  }

  function transferFrom(address from, address to, uint256 amount) external returns (bool) {
    if (allowance[from][msg.sender] != UINT256_MAX) {
      allowance[from][msg.sender] -= amount;
    }

    _transfer(from, to, amount);

    return true;
  }

  function permit(address _owner, address _spender, uint256 amount, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
    require(deadline >= block.timestamp, "QST: PERMIT_CALL_EXPIRED");

    bytes32 digest = keccak256(
      abi.encodePacked(
        "\x19\x01",
        DOMAIN_SEPARATOR,
        keccak256(
          abi.encode(
            PERMIT_TYPEHASH,
            _owner,
            _spender,
            amount,
            nonces[_owner]++,
            deadline
          )
        )
      )
    );

    address signer = ecrecover(digest, v, r, s);
    require(signer != address(0) && signer == _owner, "QST: INVALID_SIGNATURE");
    _approve(_owner, _spender, amount);
  }

  function transferOwnership(address newOwner) public isOwner {
    owner = newOwner;
  }

  function tradeable(bool toggle) public isOwner {
    liveTrading = toggle; // toggle live trading true/false
  }
  
  // Recover stuck native tokens (ETH)
  function removeStuckNative() external isOwner {
    payable(msg.sender).transfer(address(this).balance);
  }

  // Recover stuck ERC20 tokens
  function removeStuckToken(address _tokenAddress) external isOwner {
    IERC20(_tokenAddress).transfer(msg.sender, IERC20(_tokenAddress).balanceOf(address(this)));
  }

  function _approve(address _owner, address _spender, uint256 amount) private {
    allowance[_owner][_spender] = amount;

    emit Approval(_owner, _spender, amount);
  }

  function _transfer(address from, address to, uint256 amount) private {
    require(liveTrading || msg.sender == owner, "QST: Trading is disabled");

    balanceOf[from] = balanceOf[from] - amount;

    unchecked {
      balanceOf[to] = balanceOf[to] + amount;
    }

    allowance[from][to] = 0;

    emit Transfer(from, to, amount);
  }

  modifier isOwner(){
    require(msg.sender == owner, "QST: NOT_OWNER");
    _;
  }
}