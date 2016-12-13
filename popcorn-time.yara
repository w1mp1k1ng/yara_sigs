rule popcorntime
{
meta:
	author = "kevin.stear@rsa.com"
	description = "string match for popcorn time PEs"

strings: 
	$str1 = "id=\"W5M0MpCehiHzreSzNTczkc9d\""

condition:
	any of ($str*)
    }