<?php

class Request{
    
    public static function decrypt(){}

    public static function checkRequest(array $requiredPostArr)
    {
        if(!isset($_POST['app_uuid'])){
            header("No app_uuid found", true, 400);
            exit;
        }else{
            if($_POST['app_uuid'] != APP_UUID){
                header("Faulty app_uuid found", true, 400);
                exit;
            }
        }

        foreach($requiredPostArr as $var){
            if(!isset($_POST[$var])){
                header('Missing ' + $var, true, 400);
                exit;
            }
        }
    }
}