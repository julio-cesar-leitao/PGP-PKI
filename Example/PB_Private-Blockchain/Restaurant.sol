// pragma solidity ^0.4.2;
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;
// pragma experimental ABIEncoderV2;

contract Delivery {
    

    struct MenuItem{
        uint id;
        uint restaurantId;
        string name;
        string description;
        uint price;
        string imageURL;
    }

    struct Restaurant {
        uint id;
        string name;
        string location;
        string description;
        string imageURL;
        uint menuCount;
        bool exists;
    }

    mapping(uint => Restaurant) public restaurants;
    mapping(uint => MenuItem) public menuItens;

    uint public restaurantsCount = 0;
    uint public menuItensCount = 0;


    function addRestaurant (string memory _name,string memory _location, string memory _description,string memory _url) public {
    restaurants[restaurantsCount] = Restaurant(restaurantsCount, _name, _location,_description,_url,0,true);
    restaurantsCount++;
    }

    function addMenuItem (uint _restaurantId,string memory _name,string memory _description,uint _price, string memory _url) public {
    require(restaurants[_restaurantId].exists);
    menuItens[menuItensCount] = MenuItem(menuItensCount, _restaurantId, _name, _description, _price, _url);
    menuItensCount++;
    restaurants[_restaurantId].menuCount++;
    }

    function getRestaurants() public view returns (Restaurant[] memory){

        Restaurant[] memory itens = new Restaurant[](restaurantsCount);
        for(uint i=0;i<restaurantsCount;i++){
            itens[i] = restaurants[i];
        }
        return itens;

    }

    function getRestaurantMenu (uint _restaurantId) public view returns (MenuItem[] memory){

        MenuItem[] memory itens = new MenuItem[](restaurants[_restaurantId].menuCount);
        uint counter = 0;
        for(uint i=0;i<menuItensCount;i++){
            if(menuItens[i].restaurantId == _restaurantId){
                itens[counter] = menuItens[i];
                counter++;
            }
        }
        return itens;
    

    }

} 