/**
      QST | a multi-chain token
        qubeswap.com
**/

// SPDX-License-Identifier: MIT
pragma solidity =0.8.17;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Capped.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/utils/Context.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract QubeSwapToken is Context, IERC20, ERC20Permit, ERC20Capped, Ownable {
  using SafeMath for unint256;
  
  string public constant name = "QubeSwapToken";
  string public constant symbol = "QST";
  uint8 public constant decimals = 18;
  uint256 public constant MAX_SUPPLY = 100000000 * 10 ** decimals; //100M

  bool public canTrade;
  address public owner;
  
  uint256 immutable public totalSupply;

  uint256 constant UINT256_MAX = type(uint256).max;

  mapping(address => uint256) private balanceOf;
  mapping (address => uint) public nonces;
  //mapping (address => uint256) public balanceOf;
  mapping (address => mapping(address => uint256)) public allowance;
  mapping(address => bool) public whitelist;

  bytes32 public immutable DOMAIN_SEPARATOR;
  bytes32 public constant PERMIT_TYPEHASH = keccak256(
    "Permit(address owner,address spender,uint256 amount,uint256 nonce,uint256 deadline)"
  ); 


  event Transfer(address indexed from, address indexed to, uint256 amount);
  event Approval(address indexed owner, address indexed spender, uint256 amount);
  
  bool public trading; // true/false
  
  constructor() ERC20Capped(MAX_SUPPLY) {
    //canTrade = true;
    owner = msg.sender;
	whitelist[msg.sender] = true;
    totalSupply = MAX_SUPPLY;
	
	balanceOf[owner()] = totalSupply;

    DOMAIN_SEPARATOR = keccak256(
      abi.encode(
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
        keccak256(bytes(name)),
        keccak256(bytes("1")),
        block.chainid,
        address(this)
      )
    );

    //unchecked {
    //  balanceOf[address(msg.sender)] = balanceOf[address(msg.sender)] + totalSupply;
    //}

    //emit Transfer(address(0), address(msg.sender), totalSupply);
	emit Transfer(address(0), owner(), totalSupply);
  }
  
  function name() public view returns (string memory) {
    return name;
  }

  function symbol() public view returns (string memory) {
    return symbol;
  }

  function decimals() public view returns (uint8) {
    return decimals;
  }

  function maxSupply() public view override returns (uint256) {
    return MAX_SUPPLY;
  }

  function balanceOf(address account) public view override returns (uint256) {
    return balanceOf[account];
  }

  function approve(address spender, uint256 amount) external returns (bool) {
    _approve(msg.sender, spender, amount);

    return true;
  }
  
  function allowance(address owner, address spender) public view override returns (uint256) {
    return allowance[owner][spender];
  }

  function increaseAllowance(address spender, uint256 addedValue) external returns (bool) {
    _approve(msg.sender, spender, allowance[msg.sender][spender] + addedValue);

    return true;
  }

  function decreaseAllowance(address spender, uint256 subtractedValue) external returns (bool) {
    _approve(msg.sender, spender, allowance[msg.sender][spender] - subtractedValue);

    return true;
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
    require(signer != address(0) && signer == _owner, "ARB: INVALID_SIGNATURE");
    _approve(_owner, _spender, amount);
  }

  function transferOwnership(address newOwner) public isOwner {
    owner = newOwner;
  }

  //function tradeable(bool active) public isOwner {
  //  canTrade = active;
  //}
  
  function removeStuckNative(address _receiver) public onlyOwner {
    payable(_receiver).transfer(address(this).balance);
  }

  function removeStuckToken(address _token, address _receiver, uint256 _amount) public onlyOwner {
    IERC20(_token).transfer(_receiver, _amount);
  }
  
  function enableTrading() external onlyOwner {
    require(!trading, "QST: Trading Already enabled");
    trading = true;
  }
  
  function setWhitelist(address _user, bool _exmpt) external onlyOwner{
    whitelist[_user] = _exmpt;
  }

  function _approve(address _owner, address _spender, uint256 amount) private {
    allowance[_owner][_spender] = amount;

    emit Approval(_owner, _spender, amount);
  }

  function _transfer(address from, address to, uint256 amount) private {
    //require(canTrade || tx.origin == owner, "ARB: NOT_TRADEABLE");
	require(from != address(0), "QST: Transfer from the zero address");
    require(to != address(0), "QST: Transfer to the zero address");
    require(amount > 0, "QST: Amount must be greater than zero");
	
	if (!whitelist[from] && !whitelist[to]) {
        // trading disabled till launch
        require(trading,"QST: Trading is disabled");
    }

    //balanceOf[from] = balanceOf[from] - amount;

    //unchecked {
    //  balanceOf[to] = balanceOf[to] + amount;
    //}
	
	balanceOf[from] = balanceOf[from].sub(
        amount,
        "QST: Insufficient balance"
    );
    balanceOf[to] = balanceOf[to].add(amount);

    allowance[from][to] = 0;

    emit Transfer(from, to, amount);
  }

  modifier isOwner(){
    require(msg.sender == owner, "QST: NOT_OWNER");
    _;
  }
}
