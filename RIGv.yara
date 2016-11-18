rule rig_ek
{
    meta:
        author = "w1mp1k1ng@gmail.com"
        description = "RIGv landing pages"
    strings:
    // Silverlight
        $str1 = "<param name=\\'initParams\\' value=\\'shell32="
        // Flash
        $str2 = "<param name=FlashVars value=\"iddqd="
        // base64
        $str3 = "==\".replace(\"fdffghe\",\"\");"
        $str4 = "=\".replace(\"fdffghe\",\"\");"
        $str5 = "\".replace(\"fdffghe\",\"\");"
        $str6 = "=\"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\";for(i=0;i<"
        $str7 = "var payload_div = window.document.createElement(\\'div\\');"
    	$str8 = "window.document.body.appendChild(payload_div);"
        
    condition:
        any of ($str*)
}
