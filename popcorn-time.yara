rule popcorntime
{
meta:
	author = "kevin.stear@rsa.com"

strings: 
	// XMP packet header
    $str1 = "id=\"W5M0MpCehiHzreSzNTczkc9d\"" 
	// Popcorn Time string match
	$str2 = "Popcorn_Time.Properties"

condition:

	$str1 and $str2
    }
    
    