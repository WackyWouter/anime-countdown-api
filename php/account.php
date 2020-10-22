<?php

class Account{

    public static function register(){
        Request::checkRequest(['username', 'password']);

        // TODO decrypt flutter username and password
        $password = $_POST['password'];
        $username = $_POST['username'];

        $user = null;


        // check if username already exists
        self::checkUsernameExists($username);

        // check if password is strong enough
        if(!up_check::passwordStrength($password)){
            return json_encode(['status'=>'nok', 'error'=>'Password is not strong enough']);
        }
        
        $uuid = up_crypt::uuid4();
        $token = self::createToken();
        

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

        return json_encode(['status' => 'ok', 'token'=> $token]);
    }
    
    public static function login(){
        Request::checkRequest(['username', 'password']);

        // TODO decrypt flutter username and password
        $password = $_POST['password'];
        $username = $_POST['username'];

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
                if(self::checkPassword($uuid, $password)){
                    $token = self::updateToken($uuid);
                    return json_encode(['status' => 'ok', 'token' => $token]);
                }
            }           
        }

        return json_encode(['status' => 'nok', 'error' => 'Password or Username is wrong']);
        
    }

    public static function changePassword(){
        Request::checkRequest(['oldPassword', 'newPassword', 'token']);

        // TODO decrypt flutter oldPassword and newPassword
        $oldPassword = $_POST['oldPassword'];
        $newPassword = $_POST['newPassword'];

        if(!self::checkToken($_POST['token'])){
            return json_encode(['status' => 'nok', 'error' => 'token expired']);
        }
        $token = $_POST['token'];

        $uuid = null;

        $stmt = up_database::prepare('SELECT uuid FROM users WHERE token = ?');
        $stmt->bind_param('s', $token);
        $stmt->execute();
        $stmt->bind_result($uuid);
        $stmt->fetch();
        if($stmt->error != null){
            $stmt->close();
            header("Server error", true, 500);
            exit;
        }
        $stmt->close();

        // check if old passwords match
        if(!self::checkPassword($uuid, $oldPassword)){
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

        // TODO decrypt flutter username
        $username = $_POST['username'];

        // check token
        if(!self::checkToken($_POST['token'])){
            return json_encode(['status' => 'nok', 'error' => 'token expired']);
        }
        $token = $_POST['token'];

        // check if username already exists
        self::checkUsernameExists($username);

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

    public static function token(){
        Request::checkRequest(['token']);

        if(self::checkToken($_POST['token'])){
            return json_encode(['status' => 'ok']);
        }else{
            return json_encode(['status' => 'nok', 'error' => 'token expired']);
        }

    }

    // TODO make a function that checks if the token is still working

    public static function checkToken($token){
        $token_db = null;
        $token_db_expire = null;

        $stmt = up_database::prepare('SELECT 
                token,
                token_expire_date
            FROM 
                users
            WHERE 
                token = ?');
        $stmt->bind_param('s', $token);
        $stmt->execute();
        $stmt->bind_result($token_db, $token_db_expire);
        $stmt->fetch();
        if($stmt->error != null){
            $stmt->close();
            header("Server error", true, 500);
            exit;
        }
        $stmt->close();

        if(strtotime($token_db_expire) < strtotime('now')){
            return false;
        }
        else{
            return true;
        }
    }

    private static function createToken(){
        $token = [
            'token' => up_crypt::uuid4(),
            'create_date' => date("Y-m-d h:i:s", strtotime('now')),
            'expire_date' => date("Y-m-d h:i:s", strtotime(TOKEN_DURATION))
        ];
        return $token;
    }

    private static function updateToken($uuid){
        $token = self::createToken();

        
        $stmt = up_database::prepare("UPDATE 
                                        users 
                                    SET 
                                        token = ?, 
                                        token_expire_date = ?, 
                                        token_create_date = ?  
                                    WHERE  
                                        uuid = ?");
        $stmt->bind_param("ssss",$token['token'], $token['expire_date'], $token['create_date'], $uuid);
        $stmt->execute();
        if($stmt->error != null){
            $stmt->close();
            header("Server error", true, 500);
            exit;
        }
        $stmt->close();

        return $token;
    }

    private static function checkPassword($user_id, $password){
        $passwordDB = null;
        
        if ($stmt = up_database::prepare('SELECT 
                                                AES_DECRYPT(password, UNHEX(SHA2(uuid, 512))) 
                                            FROM 
                                                users 
                                            WHERE 
                                                uuid = ?')) {
            $stmt->bind_param('s', $user_id);
            $stmt->execute();
            $stmt->bind_result($passwordDB);
            $stmt->fetch();
            
            
            if($password === $passwordDB){
                $stmt->close();
                return true;
            }                     
        }
        $stmt->close();
        return false;
    }

    private static function checkUsernameExists($username){
        $user = null;
        
        $stmt = up_database::prepare('SELECT 
                AES_DECRYPT(username, UNHEX(SHA2(uuid, 512))) 
            FROM 
                users
            WHERE 
                AES_DECRYPT(username, UNHEX(SHA2(uuid, 512))) = ?');
        $stmt->bind_param('s', $username);
        $stmt->execute();
        $stmt->bind_result($user);
        $stmt->fetch();
        if($stmt->error != null){
            $stmt->close();
            header("Server error", true, 500);
            exit;
        }
        $stmt->close();

        if($user != null){
            return json_encode(['status'=>'nok', 'error'=>'Username already in use']);
        }
    }
}