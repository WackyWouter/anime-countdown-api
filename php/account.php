<?php

class Account{

    public static function register(){
        Request::checkRequest(['username', 'password']);

        // decrypt flutter username and password
        $password = Request::decrypt($_POST['password']);
        $username = Request::decrypt($_POST['username']);

        // check if username already exists
        Request::checkUsernameExists($username);

        // check if password is strong enough
        if(!up_check::passwordStrength($password)){
            return json_encode(['status'=>'nok', 'error'=>'Password is not strong enough']);
        }
        
        $uuid = up_crypt::uuid4();
        $token = Request::createToken();
        

        // add account to db
        $stmt = up_database::prepare('INSERT INTO users(
                                            uuid, 
                                            username, 
                                            password, 
                                            token, 
                                            token_expire_date, 
                                            token_create_date, 
                                            adddate) 
                                        VALUES (
                                            ?,
                                            AES_ENCRYPT(?, UNHEX(SHA2(?, 512))), 
                                            AES_ENCRYPT(?, UNHEX(SHA2(?, 512))),
                                            ?,
                                            ?,
                                            ?,
                                            NOW()
                                        )');
        $stmt->bind_param('ssssssss', $uuid, $username, $uuid, $password, $uuid, $token['token'], $token['expire_date'], $token['create_date']);
        $stmt->execute();
        if($stmt->error != null){
            $stmt->close();
            header("Server error", true, 500);
            exit;
        }    
        $stmt->close();

        return json_encode(['status' => 'ok', 'token'=> $token]);
    }
    
    public static function login(){
        Request::checkRequest(['username', 'password']);

        // decrypt flutter username and password
        $password = Request::decrypt($_POST['password']);
        $username = Request::decrypt($_POST['username']);

        if ($stmt = up_database::prepare('SELECT 
                                                uuid
                                            FROM 
                                                users
                                            WHERE 
                                                AES_DECRYPT(username, UNHEX(SHA2(uuid, 512))) = ?')) {
            $stmt->bind_param('s', $username);
            $stmt->execute();
            $stmt->store_result();

            $uuid = '';


            if ($stmt->num_rows > 0) {
                $stmt->bind_result($uuid);
                $stmt->fetch();
                if(Request::checkPassword($uuid, $password)){
                    $token = Request::updateToken($uuid);
                    $stmt->close();
                    return json_encode(['status' => 'ok', 'token' => $token]);
                }
            }           
        }
        $stmt->close();

        return json_encode(['status' => 'nok', 'error' => 'Password or Username is wrong']);
        
    }

    public static function changePassword(){
        Request::checkRequest(['oldPassword', 'newPassword', 'token']);

        // decrypt flutter oldPassword and newPassword
        $oldPassword = Request::decrypt($_POST['oldPassword']);
        $newPassword = Request::decrypt($_POST['newPassword']);

        if(!Request::checkToken($_POST['token'])){
            return json_encode(['status' => 'nok', 'error' => 'token expired']);
        }
        $token = $_POST['token'];

        $uuid = Request::getUuidByToken($token);

        // check if old passwords match
        if(!Request::checkPassword($uuid, $oldPassword)){
            return json_encode(['status' => 'nok', 'error' => 'Old password is incorrect']);
        }

        // update password
        $stmt = up_database::prepare("UPDATE 
                                        users 
                                    SET 
                                        password =  AES_ENCRYPT(?, UNHEX(SHA2(uuid, 512)))
                                    WHERE  
                                        uuid = ?");
        $stmt->bind_param("ss",$newPassword, $uuid);
        $stmt->execute();
        if($stmt->error != null){
            $stmt->close();
            header("Server error", true, 500);
            exit;
        }
        $stmt->close();
        
        return json_encode(['status' => 'ok']);


    }

    public static function changeUsername(){
        Request::checkRequest(['username', 'token']);

        // decrypt flutter username
        $username = Request::decrypt($_POST['username']);

        // check token
        if(!Request::checkToken($_POST['token'])){
            return json_encode(['status' => 'nok', 'error' => 'token expired']);
        }
        $token = $_POST['token'];

        // check if username already exists
        Request::checkUsernameExists($username);

        // update username
        $stmt = up_database::prepare("UPDATE 
                                        users 
                                    SET 
                                        username =  AES_ENCRYPT(?, UNHEX(SHA2(uuid, 512)))
                                    WHERE  
                                        token = ?");
        $stmt->bind_param("ss",$username, $token);
        $stmt->execute();
        if($stmt->error != null){
            $stmt->close();
            header("Server error", true, 500);
            exit;
        }
        $stmt->close();
        
        return json_encode(['status' => 'ok']);
    }

    
}