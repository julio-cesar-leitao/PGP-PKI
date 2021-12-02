pragma solidity ^0.4.2;

contract PKI {
    // Model a MilitaryOrganization (MO)
    struct MilitaryOrganization {
        uint id;
        string name;
        address addr;
        string email;
        string publicKey;
    }
    
    ////////////////////
    // Map PublicKey of Technical users
    mapping(address => bool) public PKtechnicalUsers;
    // Store PKtechnicalUsers Count
    uint public PKtechnicalUsersCount;
    // Store id of MilitaryOrganization already registered
    mapping(uint => bool) public MilitaryOrganizationRegistered;
    // Map each id of MilitaryOrganization and its structure
    mapping(uint => MilitaryOrganization) public MilitaryOrganizations;
    // Store MO count
    uint public MilitaryOrganizationRegisteredCount;
    ////////////////////


    // Contract constructor, initializes with all the PKtechnicalUsers,
    // After this, no one can add or remove one PKtechnicalUsers
    constructor () public {
        addPKTechnicalUsers(0x5355Ed26a59bd3712145c4b821faE788F4Fc48e5);
        // Paste more lines for the other keys of the Technical Users
        
        // Initial MilitaryOrganization example, just for tests
        createMilitaryOrganization(11031,"QGdoJulio", 0xa636B909f8Dc044c7281aad6A87A6C8AfE9B2ba3,"QGdoJulio@email.com", "");
        createMilitaryOrganization(11032,"QGdoRicardo", 0x98a5B08317122F156E6C2E1B280310CAB9F18774,"QGdoRicardo@email.com", "");
        // In the running version of this contract this line above needs to be commented
    }
    
    // It receives a pk (an address) and maps to PKtechnicalUsers
    function addPKTechnicalUsers (address _addr) private {
        PKtechnicalUsers[_addr] = true;
        PKtechnicalUsersCount++;
    }

    // Only PKtechnicalUsers must creat an MilitaryOrganization and all they must have different ids
    function createMilitaryOrganization ( uint _id, string _name, address _addr, string _email, string _pubkey) public {
        require(PKtechnicalUsers[msg.sender]);
        require(!MilitaryOrganizationRegistered[_id]);
        MilitaryOrganizations[_id] = MilitaryOrganization(_id, _name, _addr, _email, _pubkey);
        MilitaryOrganizationRegistered[_id] = true;
        MilitaryOrganizationRegisteredCount++;
    }
    
    function resetAddr(uint _id, address _addr) public {
        require(msg.sender == MilitaryOrganizations[_id].addr);
        MilitaryOrganizations[_id].addr = _addr;
    }

    function resetEmail(uint _id, string _email) public {
        require(msg.sender == MilitaryOrganizations[_id].addr);
        MilitaryOrganizations[_id].email = _email;
    }
    
    function resetPublicKey(uint _id, string _publicKey) public {
        require(msg.sender == MilitaryOrganizations[_id].addr);
        MilitaryOrganizations[_id].publicKey = _publicKey;
    }
    
    function getMilitaryOrganization(uint _id) view public returns( uint, string, address, string, string) {
        return (MilitaryOrganizations[_id].id,
        MilitaryOrganizations[_id].name,
        MilitaryOrganizations[_id].addr,
        MilitaryOrganizations[_id].email,
        MilitaryOrganizations[_id].publicKey);
    }
}
