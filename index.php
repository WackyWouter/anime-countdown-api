<?php
require_once 'usefull-php/up_database.php';
require_once 'usefull-php/up_check.php';
require_once 'usefull-php/up_crypt.php';
require_once 'php/account.php';
require_once 'php/fav.php';
require_once 'php/request.php'; 

$data = json_decode(file_get_contents('php://input'), true);

if (!$_SERVER['REQUEST_METHOD'] === 'POST') {
    echo "test";
    header("HTTP/1.1 400 Faulty request");
    exit;
}

// require_once __DIR__ . '/_autoload.php';

up_database::$host = DB_HOST;
up_database::$dbname = DB_NAME;
up_database::$username = DB_UID;
up_database::$passwd = DB_PWD;

if (isset($_POST['action'])) {
    # Get JSON as a string
    $json_str = file_get_contents('php://input');
    
    $action = $_POST['action'];
    switch ($action) {
        case 'login':
            echo Account::login();
            break;
        case 'register':
            echo Account::register();
            break;
        case 'token':
            echo Account::token();
            break;
        case 'changePassword':
            echo Account::changePassword();
            break;
        case 'changeUsername':
            echo Account::changeUsername();
            break;
        case 'addFav':
            echo Fav::addFav();
            break;
        case 'deleteFav':
            echo Fav::deleteFav();
            break;
        case 'getFav':
            echo Fav::getFav();
            break;
        default:
            exit('404 call not found');
    }
}else{
    header("HTTP/1.1 400 Faulty request");
}