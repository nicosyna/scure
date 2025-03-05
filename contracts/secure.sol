// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {KRNL, KrnlPayload, KernelParameter, KernelResponse} from "./KRNL.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";

contract SecureAccessControl is KRNL, Ownable, ReentrancyGuard {
    using ECDSA for bytes32;
    using Math for uint256;

    struct Admin {
        address adminAddress;
        bool isActive;
        uint256 nonce;
    }

    mapping(address => Admin) public admins;
    uint256 public totalAdmins;
    uint256 public requiredQuorum;
    uint256 public lastLockdownTimestamp;
    uint256 public constant LOCKDOWN_COOLDOWN = 1 hours;

    event AdminAdded(address indexed newAdmin);
    event AdminRemoved(address indexed removedAdmin);
    event Broadcast(address sender, uint256 score, string message);
    event EmergencyLockdown(address triggeredBy);
    event AdminAction(address indexed admin, string action);
    event KernelResponseError(address sender, string reason);

    modifier onlyAdmin() {
        require(admins[msg.sender].isActive, "Not an authorized admin");
        _;
    }

    modifier onlyWithQuorum(uint256 approvals) {
        require(approvals >= requiredQuorum, "Not enough approvals");
        _;
    }

    constructor(address _tokenAuthorityPublicKey) KRNL(_tokenAuthorityPublicKey) {
        admins[msg.sender] = Admin(msg.sender, true, 0);
        totalAdmins = 1;
        requiredQuorum = 1;
    }

    function addAdmin(address _newAdmin, bytes memory signature) external onlyAdmin onlyWithQuorum(totalAdmins.ceilDiv(2)) {
        require(!admins[_newAdmin].isActive, "Already an admin");
        require(_verifyAdminSignature(_newAdmin, signature), "Invalid admin signature");
        
        admins[_newAdmin] = Admin(_newAdmin, true, 0);
        totalAdmins++;
        requiredQuorum = totalAdmins.ceilDiv(2);

        emit AdminAdded(_newAdmin);
        emit AdminAction(msg.sender, "Added new admin");
    }

    function removeAdmin(address _admin, bytes memory signature) external onlyAdmin onlyWithQuorum(totalAdmins.ceilDiv(2)) {
        require(admins[_admin].isActive, "Not an admin");
        require(totalAdmins > 1, "Cannot remove the last admin");
        require(_verifyAdminSignature(_admin, signature), "Invalid admin signature");
        
        delete admins[_admin];
        totalAdmins--;
        requiredQuorum = totalAdmins.ceilDiv(2);

        emit AdminRemoved(_admin);
        emit AdminAction(msg.sender, "Removed admin");
    }

    function protectedFunction(
        KrnlPayload memory krnlPayload,
        string memory input
    ) external nonReentrant onlyAuthorized(krnlPayload, abi.encode(input)) {
        KernelResponse[] memory kernelResponses = abi.decode(krnlPayload.kernelResponses, (KernelResponse[]));
        uint256 score;
        bool found = false;
        
        for (uint i = 0; i < kernelResponses.length; i++) {
            if (kernelResponses[i].kernelId == 337 && kernelResponses[i].result.length > 0) {
                score = abi.decode(kernelResponses[i].result, (uint256));
                found = true;
                break;
            }
        }
        
        if (!found) {
            emit KernelResponseError(msg.sender, "No valid response from Kernel 337");
            return;
        }
        
        emit Broadcast(msg.sender, score, input);
    }

    function triggerEmergencyLockdown() external onlyAdmin {
        require(block.timestamp >= lastLockdownTimestamp + LOCKDOWN_COOLDOWN, "Lockdown cooldown active");
        lastLockdownTimestamp = block.timestamp;
        emit EmergencyLockdown(msg.sender);
        emit AdminAction(msg.sender, "Triggered emergency lockdown");
    }

    function _verifyAdminSignature(address admin, bytes memory signature) internal view returns (bool) {
        bytes32 messageHash = keccak256(abi.encodePacked(admin, address(this), admins[admin].nonce));
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        address recoveredAddress = ethSignedMessageHash.recover(signature);
        return admins[recoveredAddress].isActive;
    }
}
