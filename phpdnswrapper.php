<?php
if(!defined('PHPDNS')) exit('ACCESS_NOT_ALLOWED');
class DNS{
	
	private $domain = "pol.com";
	private $ip_addr = "server ip address";
	private $ns1 = "ns1.smgnames.com";
	private $ns2 = "ns2.smgnames.com";
	private $path_entry = "/var/lib/bind/";
	private $path_definition = "/etc/bind/named.conf.local";
	private $result = array();
	
	function __construct(){
		
	}

	public function list_domain(){

		$path = $this->path_entry;
		
		foreach (glob("$path*") as $filename){
			$result = str_replace("$path","", $filename);
			$result = $this->strip_file_extension($result, "hosts","rev");
			$lines = file($filename);
			$ext = explode(" ",preg_replace('!\s+!', ' ',$lines[11]));
			$this->results["success"] = true;
			$this->results["domain"][] = array("domain"=>$result ,"ip_addr"=> $ext[3],"last_update"=>date("F d Y H:i:s",filectime($filename)));		
		}
		
		return $this->results;		
	}
	
	public function add_domain_entry($domain){
		
		if($this->check_domain_file_exist($domain)){ 
			$this->result["success"] = false;
			$this->result["error"][] = "Error 0000123. $domain already in the server.";
			return $this->result;
			exit();
		}	
		
		$zone_path_file_definition =  $this->path_definition;
		$zone_path_file_entry = $this->path_entry . $domain.".hosts";
		
		$perm_def_file =  substr(sprintf('%o', fileperms($zone_path_file_definition)), -4); //check the file permission
		if($perm_def_file == 0644) chmod($zone_path_file_definition, 0777); //change to writable
		#chmod($zone_path_file_definition, 0777);
		$zone_file_definition = file_get_contents($zone_path_file_definition); //open the file
		
		//zone definition
		$zone_definition = 'zone    "$domain" {\n' ;
		$zone_definition .=  '    type    master\n';
		$zone_definition .=  '    file    "$zone_path_file_entry "\n';
		$zone_definition .= '};\n';
		
		if(file_put_contents($zone_file_definition, $zone_definition,  FILE_APPEND | LOCK_EX) !== false){
			chmod($zone_path_file_definition, 0644)
		}
		
		$zone_file_entry = fopen($zone_path_file_entry, "w");
		chmod($zone_file_entry, 0777);
		#zone entry
		$serial = urlEncode(date("Ymd").'01');
		
		$zone_entry = '\$ttl 38400\n';
		$zone_entry .= '$domain.    IN    SOA   $ns1.    root.$domain. (\n';
		$zone_entry .= '            $serial\n';
		$zone_entry .= '             10800\n';
		$zone_entry .= '             3600\n';
		$zone_entry .= '             604800\n';	
		$zone_entry .= '              38400 )\n';
		$zone_entry .= '$domain.    IN   NS    $ns1.\n';
		$zone_entry .= '$domain.    IN   NS    $ns2.\n';
		$zone_entry .= '$domain.    IN   A       $$ip_addr\n';
		$zone_entry .= 'www           IN    CNAME   $domain.';
		
		if(file_put_contents($zone_file_entry, $zone_entry, LOCK_EX) !== false){
			chmod($zone_file_entry, 0644); //change to writable
		}
		//check for the second time
		if($this->check_domain_file_exist($domain)){ 
			
			//since we can't touch the bind daemon using php shell directly,  wrap it in C code to manipulate the root uid
			
			if(exec("namedcheckconf", $output, $retval)){
				
				if($retval == 1 && !empty($output)) {
					$this->result["success"] = false;
					$this->result["error"][] = "Something went wrong. Error in  bind configuration";
					break;
				}	
			}
			if(exec("namedcheckzone $domain $zone_file_entry", $output, $retval)){
				
				$flag = false;
				
				foreach(preg_split("/((\r?\n)|(\r\n?))/", $output) as $line){
					if(preg_match('/OK/', $line)) {
						$flag = true;
						break;
					}
				}
				if(!$flag){
					
					$this->result["success"] = false;
					$this->result["error"][] = "Something went wrong. set zone entry correcty!";
					break;
				}
			}
			if(exec("bind_reload", $output, $retval)){
				if($retval != 1 && preg_match('/OK/', $output)) {
					$this->result["success"] = true;
				}else{
					$this->result["success"] = false;
					$this->result["error"][] = "Something went wrong. Cannot reload the bind9 service!";
				}
			}
			
		}else{
			$this->result["success"] = false;
			$this->result["error"][] = "Error 00456. Zone file not created.";
		}
		
		return $this->result;
			
	}
	
	public function delete_domain($domain){
		
		$path_file_definition = $this->path_definition;
		$path_entry_file = $this->path_entry . $domain . ".hosts";
		$perm = substr(sprintf('%o', fileperms($path_file_definition)), -4); //get the file permission
		if($perm == 0644) chmod($path_file_definition, 0777); //set to writable
		$lines = file($path_file_definition);
		
		$found = false;
		
		foreach($lines as $line_number=>$line){
			if(strpos($line, $domain)!==false){
				$found = true;
				$line_number++;
				break;
			}		
		}
		if($found){
			$new_line_number = $line_number - 1;
			
			for($i=0;$i<=4;$i++){  //delete 5 lines
				unset($lines[$new_line_number + $i]);
			}
			//reindex the array
			$lines = array_values($lines);
			//write back to file
			if(file_put_contents($path_file_definition, implode($lines)) !== false){
				chmod($path_file_definition, 0644);
				unlink($path_entry_file);
				$this->result["success"] = true;
			}else{
				chmod($path_file_definition, 0644);
				$this->result["success"] = false;
				$this->result["error"][] = "Error in deleting the domain $domain";
			}
		}else{
				$this->result["success"] = false;
				$this->result["error"][] = "domain not found in the server.";			
		}
		
		return $this->result;
		
	}

	public function add_sub_domain($domain, $subdomain, $subdomain_ip_addr){

		$path_entry_file = $this->path_entry . $domain . ".hosts";
		if(!check_valid_domain($domain) or !check_valid_domain($subdomain)) break; //check if valid domain
		if(!check_valid_ipv4($subdomain_ip_addr)) break;
		if(check_domain_file_exist($path_entry_file)){
			chmod($path_entry_file, 0777); //temporarily change the file permission		
		}else{
			$this->result["success"]  = false;
		}	
		
		$insert_sub_domain = "$subdomain.		IN		A		$subdomain_ip_addr";
		
		if(file_put_contents($path_entry_file, $insert_sub_domain, FILE_APPEND | LOCK_EX) !== false){
			chmod($path_entry_file, 0644); //reset permission
			$this->result["success"] = true;
		}else{
			chmod($path_entry_file, 0644); //reset permission
			$this->result["success"] = false;
			$this->result["error"][] = "Error. adding subdomain unsuccessfully!";
		}
		return $this->result;
	}

	public function add_alias_domain($domain, $name_alias, $domain_name_alias){
	
		$path_entry_file = $this->path_entry . $domain . ".hosts";
		if(!check_valid_domain($domain) or !check_valid_domain($domain_name_alias)) break; 
		if(check_domain_file_exist($path_entry_file)){
			chmod($path_entry_file, 0777); //temporarily change the file permission
			$insert_sub_domain = "$subdomain.		IN		A		$subdomain_ip_addr";
		}else{
			chmod($path_entry_file, 0644); //reset permission
			$this->result["success"]  = false;
		}
		return $this->result;
	}
	//strip file extension
	private function strip_file_extension($filename){
		$args = func_get_args();
		for ($i = 1; $i < count($args); $i++) {
				$ext = $args[$i];
				$ext_pos = strrpos($filename, '.' . $ext);
				if ($ext_pos != false && $ext_pos + strlen($ext) == strlen($filename) - 1) {
						return(substr($filename, 0, $ext_pos));
				}
		}
		return($filename);		
	}
	private function check_domain_file_exist($domain_filename){
		return file_exists($domain_filename) ? true : false;
	}
	
	private function check_valid_domain($domain){
		$result = (preg_match("/^([a-z\d](-*[a-z\d])*)(\.([a-z\d](-*[a-z\d])*))*$/i", $domain) &&
				preg_match("/^.{1,253}$/", $domain) && preg_match("/^[^\.]{1,63}(\.[^\.]{1,63})*$/", $domain));
		
		$to_return = (!$result < 1 ) ? true : false; 		
		
		return $to_return; 
	}
	
	private function check_valid_ipv4($ip_addr){
		return filter_var($ip_addr, FILTER_VALIDATE_IP) ? true : false;
	}
}
//authenticate by pam module
class PamAuth{
	public function authenticate($username, $password){
		if(exec("pamlogin $username $password", $output, $retval)){
			if($output == "Authenticated"){
				$nonce = new Nonce();
				$secret = "af45wdfqwer3";
				$token = $nonce::generate($secret);
				return $token;				
			}else{
				return "Login Failed";
			}
		}
	}
}
//authenticate by file
class Authentication{

	private function find_encrypted_password_for($username){
		
		$f = fopen("/etc/shadow","r");
		
		if ($f == null) return null;
		
		$enc = null;
		
		while (!feof($f)) {
			$line = fgets($f,4096);
			echo $line."\n";
			$i = strpos($line,":");
			if ($i == false) continue;
			$user = substr($line,0,$i);
			if ($user != $username) continue;
			$j = strpos($line,":",$i+1);
			if ($j == false) continue;
			$enc = substr($line,$i+1,$j-($i+1));
			break;
		}
		fclose($f);
		return $enc;			
	}
	public function authenticate($username, $password){
		$enc = find_encrypted_password_for($username);
		if ($enc <> null && crypt($password, $enc) === $enc){
		
			$nonce = new Nonce();
			$secret = "af45wdfqwer3";
			$token = $nonce::generate($secret);
			return $token;
			
		}else{
			return "Login failed.";
		}	
	}
}

class Nonce{
	
	private static function generate_salt($len=20){
		$fp = @fopen('/dev/urandom','rb');
		$result = '';
		if($fp !== FALSE)
		{
			$result .=@fread($fp, $len);
			@fclose($fp);
		}else{
			return "error";
		}
		
		$result = base64_encode($result);
		$result = strtr($result, '+/','-_');
		$result = str_replace("=",'',$result);
		return $result;			
	}
	
	public static function generate($secret, $timeout_seconds=180){
		if(is_string($secret) == false || str_len($secret < 10)){
			throw new InvalidArgumentException("missing valid secret!");
		}
		$salt = self::generate_salt(10);
		$time = time(); //get the current time
		$max_time = $time + $timeout_seconds; //set the maximum time nonce available
		$nonce = $salt.",".$max_time.",".sha1($salt.$secret, $max_time);
			
		return $nonce;	
		
	}	
	public static function check($secret, $nonce){
		if (is_string($nonce) == false) {
			return false;
		}
		$a = explode(',', $nonce);
		if (count($a) != 3) {
			return false;
		}
		$salt = $a[0];
		$max_time = intval($a[1]);
		$hash = $a[2];
		$back = sha1( $salt . $secret . $max_time );
		if ($back != $hash) {
			return false;
		}
		if (time() > $max_time) {
			return false;
		}
		return true;		
	}
}
