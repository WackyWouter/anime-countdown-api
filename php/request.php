<?php

class Request{
    public static $data = null;
    
    public static function decrypt($text){
        return openssl_decrypt($text, METHOD, KEY, 0, IV);
    }

    public static function checkRequest(array $requiredPostArr)
    {
        if(!isset(self::$data['app_uuid'])){
            header("No app_uuid found", true, 400);
            exit;
        }else{
            if(self::$data['app_uuid'] != APP_UUID){
                header("Faulty app_uuid found", true, 400);
                exit;
            }
        }

        foreach($requiredPostArr as $var){
            if(!isset(self::$data[$var])){
                header('Missing ' + $var, true, 400);
                exit;
            }
        }
    }

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

    public static function getUuidByToken($token){
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

        if($uuid == null){
            return json_encode(['status' => 'nok', 'error' => 'user not found']);
        }
        return $uuid;
    }

    public static function createToken(){
        $token = [
            'token' => up_crypt::uuid4(),
            'create_date' => date("Y-m-d h:i:s", strtotime('now')),
            'expire_date' => date("Y-m-d h:i:s", strtotime(TOKEN_DURATION))
        ];
        return $token;
    }

    public static function updateToken($uuid){
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

    public static function checkPassword($user_id, $password){
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

    public static function checkUsernameExists($username){
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