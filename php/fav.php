<?php

class Fav{

    public static function addFav(){
        Request::checkRequest(['token', 'anilistId']);

        // check token
        if(!Account::checkToken($_POST['token'])){
            return json_encode(['status' => 'nok', 'error' => 'token expired']);
        }
        $token = $_POST['token'];

        $uuid = Account::getUuidByToken($token);

        $stmt = up_database::prepare('INSERT INTO user_fav(
                                            user_uuid, 
                                            anilist_id
                                            )
                                        VALUES (?, ?) ON DUPLICATE KEY UPDATE id=id');
        $stmt->bind_param('si', $uuid, $_POST['anilistId']);
        $stmt->execute();
        if($stmt->error != null){
            $stmt->close();
            header("Server error", true, 500);
            exit;
        }
        $stmt->close();

        return json_encode(['status' => 'ok']);

    }

    public static function deleteFav(){
        Request::checkRequest(['token', 'anilistId']);

        // check token
        if(!Account::checkToken($_POST['token'])){
            return json_encode(['status' => 'nok', 'error' => 'token expired']);
        }
        $token = $_POST['token'];

        $uuid = Account::getUuidByToken($token);

        $stmt = up_database::prepare("DELETE FROM user_fav WHERE user_uuid = ? AND anilist_id = ? ");
        $stmt->bind_param('si', $uuid, $_POST['anilistId']);
        $stmt->execute();
        if($stmt->error != null){
            $stmt->close();
            header("Server error", true, 500);
            exit;
        }
        $stmt->close();

        return json_encode(['status' => 'ok']);

    }

    public static function getFav(){
        Request::checkRequest(['token']);

        // check token
        if(!Account::checkToken($_POST['token'])){
            return json_encode(['status' => 'nok', 'error' => 'token expired']);
        }
        $token = $_POST['token'];

        $uuid = Account::getUuidByToken($token);
        $animeIdArr = [];
        $animeId = null;

        $stmt = up_database::prepare('SELECT anilist_id FROM user_fav WHERE user_uuid = ?');
        $stmt->bind_param('s', $uuid);
        $stmt->execute();
        $stmt->bind_result($animeId);
        while($stmt->fetch()){
            $animeIdArr[] = $animeId;
        }
        if($stmt->error != null){
            $stmt->close();
            header("Server error", true, 500);
            exit;
        }
        $stmt->close();

        return json_encode(['status' => 'ok', 'animeList' => $animeIdArr]);
    }
}